use const_format::concatcp;
use cstr::cstr;
use nix::{
    errno::Errno,
    fcntl::OFlag,
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
        execv,
        fork,
        getpid,
        pipe2,
        setsid,
        write,
    },
};
use std::{
    convert::Infallible,
    ffi::CStr,
    os::unix::prelude::RawFd,
};
use precisej_printable_errno::{
    ErrnoResult,
    ExitErrorResult,
    PrintableErrno,
    PrintableResult,
    printable_error,
};

use crate::{
    platforms,
    PROGRAM_NAME,
};


const SERVICED_ARG0: &'static str = "serviced";
#[allow(dead_code)] const SERVICED_ARG1: &'static str = "initd";
const SERVICED_PATH: &'static str = concatcp!("/sbin/", SERVICED_ARG0);
const SERVICED_ERROR: &'static str = concatcp!("unable to execute serviced in ", SERVICED_PATH);

const LINUX_TIME_ALARM_DEFAULT: u32 = 30;
const LINUX_TIME_ALARM_SHORT: u32 = 1;


pub(crate) fn initial_sanity_check() -> Result<(), PrintableErrno> {
    let pid = getpid().as_raw();
    if pid != 1 {
        let e = printable_error(PROGRAM_NAME, format!("expected PID 1, got {}.", pid));

        // Running initd as a regular process shouldn't be permitted in release mode, but it makes
        // for easy testing in debug mode.
        if cfg!(debug_assertions) {
            e.eprint();
            printable_error(PROGRAM_NAME, "continuing anyway...".to_string()).eprint();
        } else {
            Err(e)?
        }
    }
    Ok(())
}

pub(crate) fn initial_setup() -> Result<(), PrintableErrno> {
    chdir("/").printable(PROGRAM_NAME, "unable to change directory to root")
}

pub(crate) fn alarm_set() {
    alarm::set(LINUX_TIME_ALARM_DEFAULT);
}

pub(crate) fn alarm_set_short() {
    alarm::set(LINUX_TIME_ALARM_SHORT);
}

pub(crate) fn alarm_clear() {
    alarm::cancel();
}

pub(crate) fn power_off() -> Result<Infallible, PrintableErrno> {
    reboot(RebootMode::RB_POWER_OFF).printable(PROGRAM_NAME, "unable to shutdown")
}

pub(crate) fn reboot_autoboot() -> Result<Infallible, PrintableErrno> {
    reboot(RebootMode::RB_AUTOBOOT).printable(PROGRAM_NAME, "unable to reboot")
}


pub(crate) struct OpaqueSigSet {
    set: SigSet,
}
impl OpaqueSigSet {
    pub(crate) fn all() -> OpaqueSigSet {
        OpaqueSigSet {
            set: SigSet::all()
        }
    }

    pub(crate) fn block(&self) -> Result<(), PrintableErrno> {
        sigprocmask(SIG_BLOCK, Some(&self.set), None)
            .printable(PROGRAM_NAME, "unable to block signals")
    }

    pub(crate) fn unblock(&self) -> Result<(), PrintableErrno> {
        sigprocmask(SIG_UNBLOCK, Some(&self.set), None)
            .printable(PROGRAM_NAME, "unable to unblock signals in child")
    }

    pub(crate) fn wait_for_next(&self) -> Result<Signal, PrintableErrno> {
        self.set.wait()
            .printable(PROGRAM_NAME, "unable to await new process signals")
    }
}

pub(crate) trait ServicedPid {
    fn pid(&self) -> Pid;
}

pub(crate) struct OpaqueServicedHandle {
    pid: Pid,
    exit_pipe: RawFd,
}
impl OpaqueServicedHandle {
    pub(crate) fn spawn_serviced(set: &OpaqueSigSet) -> Result<OpaqueServicedHandle, PrintableErrno> {
        let (read_exit_pipe, write_exit_pipe) = pipe2(OFlag::O_NONBLOCK)
            .printable(PROGRAM_NAME, "unable to create critical communication channel with serviced")?;

        // SAFETY: The string will always be an integer followed by a nul byte.
        let serviced_exit_pipe_arg2_s = format!("{}\0", read_exit_pipe).into_bytes();
        let serviced_exit_pipe_arg2 = unsafe { CStr::from_bytes_with_nul_unchecked(&serviced_exit_pipe_arg2_s) };

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
                set.unblock().ok_or_perror();

                close(write_exit_pipe)
                    .printable(PROGRAM_NAME, "serviced: unable to close duplicate communication channel end with initd")
                    .ok_or_perror();

                // All we have to do now is change session / process group id and hand over
                // execution to serviced. Realistically the only error that could arise is
                // SERVICED_PATH not being found (root not properly mounted or no serviced/
                // serviced-compatible program installed), so just begrudgingly bail and hope
                // any distro maintainer fixes whatever crap package manager dependency
                // management they have that permits installing ONLY initd.
                setsid().printable(PROGRAM_NAME, "unable to change session id").ok_or_perror();
                let err = execv(cstr!(SERVICED_PATH), &[cstr!(SERVICED_ARG0), cstr!(SERVICED_ARG1), serviced_exit_pipe_arg2])
                    .printable(PROGRAM_NAME, SERVICED_ERROR)
                    .bail(7);

                // Indeed there is no serviced (or it is not accessible via SERVICED_PATH),
                // so close any remaining pipes and bail.
                close(read_exit_pipe)
                    .printable(PROGRAM_NAME, "serviced: unable to clean up communication channel end with initd")
                    .ok_or_perror();
                err.unwrap_or_signal_safe_exit();
                unreachable!()
            }
            Err(errno) => {
                // fork() failing should be a fatal error, so bubble up a printable error.
                return Err(errno).printable(PROGRAM_NAME, "unable to fork child for execution");
            }
        };

        Ok(OpaqueServicedHandle {
            pid,
            exit_pipe: read_exit_pipe,
        })
    }

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

pub(crate) struct OpaqueClosingServicedInstance {
    pid: Pid,
}
impl ServicedPid for OpaqueClosingServicedInstance {
    fn pid(&self) -> Pid {
        self.pid
    }
}