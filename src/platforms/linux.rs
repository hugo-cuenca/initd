//!
//!
//! This module contains specific libc Linux system calls to be performed when
//! calling into [crate::platforms] on a Linux OS.

use cfg_if::cfg_if;
use cstr::cstr;
use nix::{
    errno::Errno,
    fcntl::{
        OFlag,
        open,
    },
    ioctl_read,
    libc::{
        STDERR_FILENO,
        STDIN_FILENO,
        STDOUT_FILENO,
    },
    sys::{
        reboot::{
            RebootMode,
            reboot,
        },
        signal::{
            SigSet,
            SigmaskHow::{
                SIG_BLOCK,
                SIG_UNBLOCK
            },
            Signal,
            sigprocmask,
        },
        stat::Mode,
        wait::{
            WaitPidFlag,
            WaitStatus,
            waitpid,
        },
    },
    unistd::{
        ForkResult,
        Pid,
        alarm,
        chdir,
        close,
        dup2,
        execv,
        fork,
        getpid,
        pipe2,
        setsid,
        sleep,
        sync,
        write,
    },
};
use std::{
    convert::Infallible,
    ffi::CStr,
    os::{
        raw::c_int,
        unix::prelude::RawFd,
    },
};
use precisej_printable_errno::{ErrnoResult, PrintableErrno, PrintableResult, printable_error, ExitErrorResult};

use crate::{
    platforms,
    PROGRAM_NAME,
};


/// Used as the 0th argument to serviced in an `execv` call.
const SERVICED_ARG0: &'static CStr = cstr!("serviced");

/// Used as the 1st argument to serviced in an `execv` call.
///
/// All initd-compatible programs should use this same constant value to indicate
/// their communication specification. serviced can parse the sent value and
/// allow communication accordingly.
#[allow(dead_code)] const SERVICED_ARG1: &'static CStr = cstr!("initd_v0");

/// Path where serviced is located. Used in the `execv` call to actually execute
/// serviced.
///
/// **Note**: if you are a distribution maintainer, make sure your serviced package
/// actually puts the executable in `/sbin/serviced`. Otherwise, you must maintain a
/// patch changing `SERVICED_PATH` to the appropriate path (e.g. `/serviced`,
/// `/bin/serviced`, or `/usr/bin/serviced`).
const SERVICED_PATH: &'static CStr = cstr!("/sbin/serviced");

/// Error message used in case `SERVICE_PATH` is not able to be executed by `execv`.
/// This can be caused by not having serviced installed (although distributions should
/// ensure proper packaging where initd depends on serviced so this won't happen),
/// not having it installed with the proper executable permissions (should never
/// happen unless serviced is improperly packaged by the distribution), or a more
/// obscure error.
const SERVICED_ERROR: &'static str = "unable to execute serviced";

/// In how many seconds the alarm should be scheduled.
///
/// As alluded to by
/// [this commit in sinit](https://git.suckless.org/sinit/commit/170d599d58efee6c9be675a85c6e435d68e8a2de.html),
/// there is a case where a parent receives `SIGCHLD` when a child dies, but exits or
/// crashes before it decides to await it. In that case, the zombie process is
/// re-parented to initd, but no `SIGCHLD` is delivered to us. In order to fix this
/// issue, we must periodically check for zombies that must be awaited, and we do
/// so via an alarm (which sends `SIGALRM` after `LINUX_TIME_ALARM_DEFAULT` seconds).
/// Since `SIGALARM` is only used for this purpose, we can always interpret that signal
/// to mean [platforms::ProcSignal::ReapChild].
const LINUX_TIME_ALARM_DEFAULT: u32 = 30;

/// In how many seconds the short alarm should be scheduled. See
/// [LINUX_TIME_ALARM_DEFAULT] for an explanation as to why this is needed.
///
/// Short alarms are used when serviced is closing, as many processes exiting at the same
/// time can more easily cause the same case to happen (maybe even multiple times
/// simultaneously), and that is unwanted when performing a shutdown or a reboot.
/// Therefore a shorter alarm that signals [platforms::ProcSignal::ReapChild] more
/// frequently is warranted.
///
/// **NOTE**: any previous alarm is cancelled when a new one is scheduled. If many
/// processes are exiting, `SIGCHLD` will be delivered frequently, causing the alarm to
/// be cancelled anyway, so having alarms be more frequent shouldn't cause performance
/// nor power-saving issues.
const LINUX_TIME_ALARM_SHORT: u32 = 1;


ioctl_read! {
    /// [ioctl(RawFd, TIOCSCTTY, *mut c_int)][nix::libc::ioctl] wrapper.
    ///
    /// Make the given terminal the controlling terminal of the calling process. The calling
    /// process must be a session leader and not have a controlling terminal already. If the
    /// terminal is already the controlling terminal of a different session group then the
    /// ioctl will fail with **EPERM**, unless the caller is root (more precisely: has the
    /// **CAP_SYS_ADMIN** capability) and arg equals 1, in which case the terminal is stolen
    /// and all processes that had it as controlling terminal lose it.
    tiocsctty, b't', 19, c_int
}


/// Initial sanity checks for Linux.
///
/// The following sanity checks should be made in Linux:
/// * We should be PID 1. Otherwise, an error should be returned.
///     * With `debug-notpid1`, we can just emit a warning and continue.
pub(crate) fn initial_sanity_check() -> Result<OpaqueSanityCheckResult, PrintableErrno> {
    let pid = getpid().as_raw();
    if pid != 1 {
        // If we aren't PID 1, assume stdin/stdout/stderr to all be open, so no problem in
        // using precisej-printable-errno here.
        let e = printable_error(PROGRAM_NAME, format!("expected PID 1, got {}.", pid));

        // Running initd as a regular process shouldn't be permitted in release mode, so it's
        // hidden behind the 'debug-notpid1' feature flag.
        cfg_if! {
            if #[cfg(feature = "debug-notpid1")] {
                e.eprint();
                printable_error(PROGRAM_NAME, "continuing anyway...".to_string()).eprint();
                Ok(OpaqueSanityCheckResult(false))
            } else {
                Err(e)
            }
        }
    } else {
        Ok(OpaqueSanityCheckResult(true))
    }
}

/// Initial setup for Linux.
///
/// The following initial setup should be made in Linux:
/// * If we are PID 1:
///     * Open `/dev/console` as read_fd and write_fd.
///     * Set read_fd as stdin.
///     * Set write_fd as stdout and stderr.
/// * Change directory to `/`.
pub(crate) fn initial_setup(results: &OpaqueSanityCheckResult) -> Result<(), PrintableErrno> {
    let is_pid1 = results.0;
    if is_pid1 {
        // Since neither stdin/stdout/stderr is assumed to be open, we can't use
        // precisej-printable-errno just yet.
        // runit repeats syscalls on failure after 5 seconds, so we will do something
        // similar here.

        let read_fd = open_console(OFlag::O_RDONLY);
        dup2_retry(read_fd, STDIN_FILENO);
        if read_fd != STDIN_FILENO {
            close(read_fd).ok(); // ignore error
        }

        let write_fd = open_console(OFlag::O_WRONLY);
        dup2_retry(write_fd, STDOUT_FILENO);
        dup2_retry(write_fd, STDERR_FILENO);
        if write_fd != STDOUT_FILENO && write_fd != STDERR_FILENO {
            close(write_fd).ok(); // ignore error
        }

        #[inline]
        fn open_console(oflag: OFlag) -> RawFd {
            loop {
                match open("/dev/console", oflag, Mode::empty()) {
                    Ok(fd) => break fd,
                    Err(_) => sleep(5),
                };
            }
        }
        #[inline]
        fn dup2_retry(oldfd: RawFd, newfd: RawFd) {
            loop {
                match dup2(oldfd, newfd) {
                    Ok(_) => break,
                    Err(_) => sleep(5),
                };
            }
        }
    }

    // At this point precisej-printable-errno should work as stdin/stdout/stderr should
    // all be opened.
    chdir("/").printable(PROGRAM_NAME, "unable to change directory to root")
}

/// Schedule a new alarm. `SIGALRM` will be delivered to the process in
/// [LINUX_TIME_ALARM_DEFAULT] seconds.
///
/// This just calls [alarm::set], which calls `alarm(2)` under the hood.
pub(crate) fn alarm_set() {
    alarm::set(LINUX_TIME_ALARM_DEFAULT);
}

/// Schedule a new short alarm. `SIGALRM` will be delivered to the process in
/// [LINUX_TIME_ALARM_SHORT] seconds.
///
/// This just calls [alarm::set], which calls `alarm(2)` under the hood.
pub(crate) fn alarm_set_short() {
    alarm::set(LINUX_TIME_ALARM_SHORT);
}

/// Clears any existing scheduled alarm.
///
/// This just calls [alarm::cancel], which calls `alarm(2)` with seconds = 0.
pub(crate) fn alarm_clear() {
    alarm::cancel();
}

/// Tell the system to sync pending disk operations and shutdown.
///
/// serviced should sync disks before exiting. However, serviced might have crashed,
/// making that assumption invalid. Linux has no "blue screen of death" for critical
/// userspace components, so we must handle the possibility of serviced crashing
/// ourselves. Therefore `sync(2)` must be called as a precautionary measure.
///
/// After calling `sync(2)`, we call `reboot(2)` with `RB_POWER_OFF`.
pub(crate) fn power_off() -> Result<Infallible, PrintableErrno> {
    sync();
    reboot(RebootMode::RB_POWER_OFF).printable(PROGRAM_NAME, "unable to shutdown")
}

/// Tell the system to sync pending disk operations and reboot.
///
/// serviced should sync disks before exiting. However, serviced might have crashed,
/// making that assumption invalid. Linux has no "blue screen of death" for critical
/// userspace components, so we must handle the possibility of serviced crashing
/// ourselves. Therefore `sync(2)` must be called as a precautionary measure.
///
/// After calling `sync(2)`, we call `reboot(2)` with `RB_AUTOBOOT`.
pub(crate) fn reboot_autoboot() -> Result<Infallible, PrintableErrno> {
    sync();
    reboot(RebootMode::RB_AUTOBOOT).printable(PROGRAM_NAME, "unable to reboot")
}


/// This contains relevant initial sanity check results.
///
/// For now the only relevant info is whether we are PID 1, as we might not be if
/// we're compiled in debug mode.
///
/// See [initial_sanity_check] and [initial_setup] for more info.
pub(crate) struct OpaqueSanityCheckResult(bool);

/// Saves signals to `SIG_BLOCK` when `block()` is called.
pub(crate) struct OpaqueSigSet {
    set: SigSet,
}
impl OpaqueSigSet {
    /// Constructs a new set with all signals. Internally calls `sigfillset(3)`.
    ///
    /// **NOTE**: even though our set contains all signals, `SIGKILL` and `SIGSTOP`
    /// can't be blocked and they are silently ignored in `sigprocmask(2)`.
    pub(crate) fn all() -> OpaqueSigSet {
        OpaqueSigSet {
            set: SigSet::all()
        }
    }

    /// Blocks the signals corresponding to this struct. Internally calls `sigprocmask(2)`.
    ///
    /// **NOTE**: even though our set contains all signals, `SIGKILL` and `SIGSTOP`
    /// can't be blocked and they are silently ignored in `sigprocmask(2)`.
    pub(crate) fn block(&self) -> Result<(), PrintableErrno> {
        sigprocmask(SIG_BLOCK, Some(&self.set), None)
            .printable(PROGRAM_NAME, "unable to block signals")
    }

    /// Unblocks the signals corresponding to this struct. Internally calls `sigprocmask(2)`.
    ///
    /// **NOTE**: even though our set contains all signals, `SIGKILL` and `SIGSTOP`
    /// can't be blocked and they are silently ignored in `sigprocmask(2)`.
    pub(crate) fn unblock(&self) -> Result<(), PrintableErrno> {
        sigprocmask(SIG_UNBLOCK, Some(&self.set), None)
            .printable(PROGRAM_NAME, "unable to unblock signals in child")
    }

    /// Waits for the next blocked signal to be delivered to this process. Internally calls
    /// `sigwait(3)`.
    ///
    /// **NOTE**: even though our set contains all signals, `SIGKILL` and `SIGSTOP`
    /// can't be blocked and they are silently ignored in `sigprocmask(2)`.
    pub(crate) fn wait_for_next(&self) -> Result<Option<platforms::ProcSignal>, PrintableErrno> {
        match self.set.wait().printable(PROGRAM_NAME, "unable to await new process signals")? {
            Signal::SIGUSR1 => Ok(Some(platforms::ProcSignal::PowerOff)),
            Signal::SIGCHLD => Ok(Some(platforms::ProcSignal::ReapChild)),
            Signal::SIGALRM => Ok(Some(platforms::ProcSignal::ReapChild)),
            Signal::SIGINT => Ok(Some(platforms::ProcSignal::Reboot)),
            _ => Ok(None),
        }
    }
}

/// Refers to the pid of a serviced instance (which may be alive, dying, or have recently
/// become a zombie).
pub(crate) trait ServicedPid {
    /// Get the pid of the serviced instance.
    fn pid(&self) -> Pid;
}

/// Refers to the pid and communication handle of a serviced instance.
pub(crate) struct OpaqueServicedHandle {
    /// Pid of the serviced instance.
    pid: Pid,

    /// serviced communication handle.
    exit_pipe: RawFd,
}
impl OpaqueServicedHandle {
    /// Spawn a new serviced instance and obtain its communication handle.
    ///
    /// The following steps are taken:
    /// * Create a non-blocking pipe with `pipe2(2)` and `O_NONBLOCK`.
    /// * `fork(2)` a new child process:
    ///     * In the child:
    ///         * Unblocks the signals corresponding to the set.
    ///         * Close initd's end of the pipe, as serviced doesn't need it.
    ///         * Create new session and process group (`setsid()`).
    ///         * Open `/dev/console` and set it as the controlling terminal
    ///           for the process group.
    ///         * `execv(3)` [SERVICED_PATH].
    ///     * In the parent:
    ///         * Close serviced's end of the pipe, as initd doesn't need it.
    ///         * Return a communication handle to the recently spawned serviced.
    pub(crate) fn spawn_serviced(set: &OpaqueSigSet, setup: OpaqueSanityCheckResult) -> Result<OpaqueServicedHandle, PrintableErrno> {
        let (read_exit_pipe, write_exit_pipe) = pipe2(OFlag::O_NONBLOCK)
            .printable(PROGRAM_NAME, "unable to create critical communication channel with serviced")?;

        // SAFETY: The string will always be an integer followed by a nul byte.
        let serviced_exit_pipe_arg2_s = format!("{}\0", read_exit_pipe).into_bytes();
        let serviced_exit_pipe_arg2 = unsafe { CStr::from_bytes_with_nul_unchecked(&serviced_exit_pipe_arg2_s) };

        let is_pid1 = setup.0;

        let pid = match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // We are still initd, so just close the unnecessary fd and save the child pid
                close(read_exit_pipe)
                    .printable(PROGRAM_NAME, "unable to close duplicate communication channel end with serviced")?;
                child
            }
            Ok(ForkResult::Child) => unsafe {
                // We are the child, which means we shouldn't exit to signal an error as it
                // will be ignored. Since we are PID1 and system has just been handed over
                // to userspace, the only error that should realistically happen is serviced
                // not being found. All other syscalls should succeed, but log any errors
                // to stdout just in case.

                // Signals were blocked by our parent, but we should unblock them to prepare
                // for handing over to serviced
                set.unblock().ok_or_eprint_signal_safe();

                close(write_exit_pipe)
                    .printable(PROGRAM_NAME, "serviced: unable to close duplicate communication channel end with initd")
                    .ok_or_eprint_signal_safe();

                // All we have to do now is change session / process group id, open /dev/console,
                // and hand over execution to serviced. Realistically the only error that could
                // arise is SERVICED_PATH not being found (root not properly mounted or no serviced/
                // serviced-compatible program installed), so just begrudgingly bail and hope any
                // distro maintainer fixes whatever crap caused this.
                setsid()
                    .printable(PROGRAM_NAME, "unable to change session id")
                    .ok_or_eprint_signal_safe();

                if is_pid1 {
                    if let Ok(fd) = open("/dev/console", OFlag::O_RDWR, Mode::empty()) {
                        tiocsctty(fd, std::ptr::null_mut()).ok(); // ignore error

                        while dup2(fd, STDIN_FILENO).is_err() { sleep(5); }
                        if fd > STDERR_FILENO {
                            close(fd).ok(); // ignore error
                        }
                    };
                }

                let err = execv(SERVICED_PATH, &[SERVICED_ARG0, SERVICED_ARG1, serviced_exit_pipe_arg2])
                    .printable(PROGRAM_NAME, SERVICED_ERROR)
                    .bail(7);

                // Indeed there is no serviced (or it is not accessible via SERVICED_PATH),
                // so close any remaining pipes and bail.
                close(read_exit_pipe)
                    .printable(PROGRAM_NAME, "serviced: unable to clean up communication channel end with initd")
                    .ok_or_eprint_signal_safe();
                err.unwrap_or_eprint_signal_safe_exit();

                // unreachable because we already exited
                std::hint::unreachable_unchecked()
            }
            Err(errno) => {
                // fork() failing should be a fatal error, so bubble up a printable error.
                return Err(errno).printable(PROGRAM_NAME, "unable to fork child for execution");
            }
        };

        Ok(OpaqueServicedHandle {
            pid,
            exit_pipe: write_exit_pipe,
        })
    }

    /// Await the next child process. The result is of type [platforms::WaitStatus] to
    /// distinguish what should be done.
    pub(crate) fn wait_next_child<S: ServicedPid>(serviced: &S) -> Result<platforms::WaitStatus, PrintableErrno> {
        let status = match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(status) => status,
            Err(Errno::ECHILD) => return Ok(platforms::WaitStatus::BreakDefault), // WNOHANG: nothing else to wait for
            Err(e) => return Err(e).printable(PROGRAM_NAME, "unable to wait for child")
        };
        let serviced_pid = serviced.pid();
        match status {
            WaitStatus::Exited(pid, exit_code) if pid == serviced_pid => {
                if exit_code != 0 {
                    printable_error(PROGRAM_NAME, format!("serviced exited with error code {}", exit_code))
                        .eprint();
                }
                Ok(platforms::WaitStatus::BreakServiced)
            },
            WaitStatus::Signaled(pid, sig, _) if pid == serviced_pid => {
                printable_error(PROGRAM_NAME, format!("serviced was killed with {}", sig.as_str())).eprint();
                Ok(platforms::WaitStatus::BreakServiced)
            },
            WaitStatus::Exited(_, _) => {
                Ok(platforms::WaitStatus::ContinueLoop)
            },
            WaitStatus::Signaled(_, _, _) => {
                Ok(platforms::WaitStatus::ContinueLoop)
            },
            WaitStatus::StillAlive => Ok(platforms::WaitStatus::BreakDefault), // WNOHANG: nothing else to wait for

            // WaitStatus::Stopped(_, _)
            // WaitStatus::PtraceEvent(_, _, _)
            // WaitStatus::PtraceSyscall(_)
            // WaitStatus::Continued(_)
            //
            // What do they have in common?
            // WNOHANG: there might be another process to wait for
            _ => Ok(platforms::WaitStatus::ContinueLoop),
        }
    }

    /// Send a message through the handle to serviced to cleanly exit, and then close the handle.
    pub(crate) fn send_exit_message(&mut self) -> Result<OpaqueClosingServicedInstance, PrintableErrno> {
        write(self.exit_pipe, &[1]).printable(PROGRAM_NAME, "unable to send exit message to serviced")?;
        close(self.exit_pipe).printable(PROGRAM_NAME, "unable to close message pipe with serviced")?;
        self.exit_pipe = -1;
        Ok(OpaqueClosingServicedInstance {
            pid: self.pid,
        })
    }
}
impl ServicedPid for OpaqueServicedHandle {
    fn pid(&self) -> Pid {
        self.pid
    }
}

/// Refers to the pid of a serviced instance that is closing, or has recently closed and
/// become a zombie.
pub(crate) struct OpaqueClosingServicedInstance {
    /// Pid of the serviced instance.
    pid: Pid,
}
impl ServicedPid for OpaqueClosingServicedInstance {
    fn pid(&self) -> Pid {
        self.pid
    }
}