//!
//!
//! Linux-specific code is located in `linux`.

use cfg_if::cfg_if;
use precisej_printable_errno::{printable_error, PrintableErrno, PrintableResult};

use crate::PROGRAM_NAME;

/// Linux-specific code is located here.
#[cfg(target_os = "linux")]
mod linux;

/// Perform basic initialization.
///
/// Contains functions to perform:
/// * Basic sanity checks (e.g. checking whether we are the proper process).
/// * Basic initial setup (e.g. changing to the root directory of the filesystem).
pub mod initializer {
    use cfg_if::cfg_if;
    use precisej_printable_errno::PrintableErrno;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    /// Contains the results of basic sanity checks.
    ///
    /// This struct exists because certain checks may not directly raise an error,
    /// but instead affect how the initial setup is done.
    ///
    /// This should be an opaque struct, as its internal representation varies
    /// from platform to platform and isn't guaranteed to be stable.
    pub struct SanityCheckResult {
        #[cfg(target_os = "linux")]
        pub(crate) opaque: linux::OpaqueSanityCheckResult,
    }

    /// Basic sanity checks. Unix-like systems check to see if we are PID1.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn initial_sanity_check() -> Result<SanityCheckResult, PrintableErrno<String>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                Ok(SanityCheckResult {
                    opaque: linux::initial_sanity_check()?
                })
            } else {
                unimplemented!()
            }
        }
    }

    /// Basic initial setup. Unix-like systems change current directory to `/`.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn initial_setup(results: &SanityCheckResult) -> Result<(), PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::initial_setup(&results.opaque)
            } else {
                unimplemented!()
            }
        }
    }
}

/// Schedule or clear pending alarms.
///
/// Contains functions to:
/// * Schedule a new alarm (clearing previous ones).
/// * Schedule a new short alarm (clearing previous ones).
/// * Clearing previous alarms.
pub mod alarm {
    use cfg_if::cfg_if;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    /// Schedule a new alarm, and clear any previous alarms.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn set() {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::alarm_set()
            } else {
                unimplemented!()
            }
        }
    }

    /// Schedule a new short alarm, and clear any previous alarms.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn set_short() {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::alarm_set_short()
            } else {
                unimplemented!()
            }
        }
    }

    /// Clear any previous alarms scheduled via [set] or [set_short].
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn clear() {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::alarm_clear()
            } else {
                unimplemented!()
            }
        }
    }
}

/// Shutdown or reboot the system.
///
/// Contains functions to perform (after syncing disks):
/// * Shutdown.
/// * Reboot.
pub mod power {
    use cfg_if::cfg_if;
    use precisej_printable_errno::PrintableErrno;
    use std::convert::Infallible;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    /// Tell the system to sync pending disk operations and shutdown.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn power_off() -> Result<Infallible, PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::power_off()
            } else {
                unimplemented!()
            }
        }
    }

    /// Tell the system to sync pending disk operations and reboot.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn reboot() -> Result<Infallible, PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::reboot_autoboot()
            } else {
                unimplemented!()
            }
        }
    }
}

/// Corresponds to a raw signal number sent to this process. Only lists
/// relevant signals.
///
/// Each platform may have a different way of presenting platform signals.
/// See the specific platform module for more details.
pub enum ProcSignal {
    /// A child process has entered zombie mode and needs to be awaited.
    ReapChild,

    /// The system must power off.
    PowerOff,

    /// The system must reboot.
    Reboot,
}

/// Contains the signals that should be intercepted.
///
/// This should be an opaque struct, as its internal representation varies
/// from platform to platform and isn't guaranteed to be stable.
pub struct ProcSignalInterceptor {
    #[cfg(target_os = "linux")]
    opaque: linux::OpaqueSigSet,
}
impl ProcSignalInterceptor {
    /// Create a new signal interceptor containing all intercept-able signals
    /// in the platform.
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn intercept_all() -> Result<ProcSignalInterceptor, PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let opaque = linux::OpaqueSigSet::all();
                opaque.block()?;
                Ok(ProcSignalInterceptor {
                    opaque
                })
            } else {
                unimplemented!()
            }
        }
    }

    /// Wait for the next intercepted signal to be delivered (or a previously
    /// delivered signal that was never handled).
    ///
    /// See the specific platform module corresponding to a target OS for
    /// more details on what is done here.
    pub fn wait_for_next(&self) -> Result<Option<ProcSignal>, PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                self.opaque.wait_for_next()
            } else {
                unimplemented!()
            }
        }
    }
}

/// Corresponds to the action that should be taken after awaiting a child process.
pub enum WaitStatus {
    /// Continue awaiting processes, as there might be more.
    ContinueLoop,

    /// There are no more processes to be awaited, so continue with the event loop.
    BreakDefault,

    /// Serviced died (unspecified if whether it just spontaneously crashed or after
    /// being told to exit).
    BreakServiced,
}

/// Refers to a serviced instance (which may be alive, dying, or have recently become a zombie).
pub trait ServicedInstance {
    /// Await the next child process. The result is of type [WaitStatus] to
    /// distinguish what should be done.
    fn wait_next_child(&self) -> WaitStatus;
}

/// Refers to a communication handle to a serviced instance, which is either
/// still alive or recently became a zombie due to it crashing and not closing
/// the handle.
///
/// This should be an opaque struct, as its internal representation varies
/// from platform to platform and isn't guaranteed to be stable.
pub struct ServicedHandle {
    #[cfg(target_os = "linux")]
    opaque: linux::OpaqueServicedHandle,
}
impl ServicedHandle {
    /// Spawn a new serviced instance with all signals unblocked. Returns a [Result]
    /// with the communication handle.
    pub fn spawn_serviced(
        set: &ProcSignalInterceptor,
        setup: initializer::SanityCheckResult,
    ) -> Result<ServicedHandle, PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                Ok(ServicedHandle {
                    opaque: linux::OpaqueServicedHandle::spawn_serviced(&set.opaque, setup.opaque)?
                })
            } else {
                unimplemented!()
            }
        }
    }

    /// Return a generic serviced instance object. It always return
    /// [ServicedInstanceGeneric::OpenHandle] and consumes self.
    pub fn to_generic(self) -> ServicedInstanceGeneric {
        ServicedInstanceGeneric::OpenHandle(self)
    }
}
impl ServicedInstance for ServicedHandle {
    //noinspection DuplicatedCode
    fn wait_next_child(&self) -> WaitStatus {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::OpaqueServicedHandle::wait_next_child(&self.opaque).ok_or_eprint().unwrap_or(WaitStatus::BreakDefault)
            } else {
                unimplemented!()
            }
        }
    }
}

/// Refers to a serviced instance that is closing, or has recently closed and
/// become a zombie.
///
/// This should be an opaque struct, as its internal representation varies
/// from platform to platform and isn't guaranteed to be stable.
pub struct ClosingServicedInstance {
    #[cfg(target_os = "linux")]
    opaque: linux::OpaqueClosingServicedInstance,
}
impl ServicedInstance for ClosingServicedInstance {
    //noinspection DuplicatedCode
    fn wait_next_child(&self) -> WaitStatus {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::OpaqueServicedHandle::wait_next_child(&self.opaque).ok_or_eprint().unwrap_or(WaitStatus::BreakDefault)
            } else {
                unimplemented!()
            }
        }
    }
}

/// Refers to a serviced instance (which may be alive, dying, or have recently become a zombie).
/// This variant enumerates possible cases.
pub enum ServicedInstanceGeneric {
    /// The communication handle is still open.
    OpenHandle(ServicedHandle),

    /// The communication handle is closed because serviced is closing.
    Closing(ClosingServicedInstance),
}
impl ServicedInstanceGeneric {
    /// If the communication handle is still open, send a message through the handle
    /// to serviced to cleanly exit, and then close the handle.
    pub fn try_send_exit_message(&mut self) -> Result<(), PrintableErrno<&'static str>> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                match self {
                    ServicedInstanceGeneric::OpenHandle(ref mut h) => {
                        *self = ServicedInstanceGeneric::Closing(ClosingServicedInstance {
                            opaque: h.opaque.send_exit_message()?
                        });
                        Ok(())
                    }
                    ServicedInstanceGeneric::Closing(_) => {
                        printable_error(PROGRAM_NAME, "trying to close nonexistent serviced communication pipe").eprint();
                        Ok(())
                    }
                }
            } else {
                unimplemented!()
            }
        }
    }
}
impl ServicedInstance for ServicedInstanceGeneric {
    fn wait_next_child(&self) -> WaitStatus {
        match self {
            ServicedInstanceGeneric::OpenHandle(h) => h.wait_next_child(),
            ServicedInstanceGeneric::Closing(i) => i.wait_next_child(),
        }
    }
}
