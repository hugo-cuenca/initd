use cfg_if::cfg_if;
use nix::sys::signal::Signal;
use precisej_printable_errno::{
    PrintableErrno,
    PrintableResult,
    printable_error,
};

use crate::PROGRAM_NAME;

#[cfg(target_os = "linux")]
mod linux;

pub mod initializer {
    use cfg_if::cfg_if;
    use precisej_printable_errno::PrintableErrno;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    pub fn initial_sanity_check() -> Result<(), PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::initial_sanity_check()
            } else {
                unimplemented!()
            }
        }
    }

    pub fn initial_setup() -> Result<(), PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::initial_setup()
            } else {
                unimplemented!()
            }
        }
    }
}

pub mod alarm {
    use cfg_if::cfg_if;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    pub fn set() {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::alarm_set()
            } else {
                unimplemented!()
            }
        }
    }

    pub fn set_short() {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::alarm_set_short()
            } else {
                unimplemented!()
            }
        }
    }

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

pub mod power {
    use cfg_if::cfg_if;
    use precisej_printable_errno::PrintableErrno;
    use std::convert::Infallible;

    #[cfg(target_os = "linux")]
    use crate::platforms::linux;

    pub fn power_off() -> Result<Infallible, PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::power_off()
            } else {
                unimplemented!()
            }
        }
    }

    pub fn reboot() -> Result<Infallible, PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                linux::reboot_autoboot()
            } else {
                unimplemented!()
            }
        }
    }
}

pub enum ProcSignal {
    ReapChild,
    PowerOff,
    Reboot,
}
pub struct ProcSignalInterceptor {
    #[cfg(target_os = "linux")]
    opaque: linux::OpaqueSigSet,
}
impl ProcSignalInterceptor {
    pub fn intercept_all() -> Result<ProcSignalInterceptor, PrintableErrno> {
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

    pub fn wait_for_next(&self) -> Result<Option<ProcSignal>, PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                match self.opaque.wait_for_next()? {
                    Signal::SIGUSR1 => Ok(Some(ProcSignal::PowerOff)),
                    Signal::SIGCHLD => Ok(Some(ProcSignal::ReapChild)),
                    Signal::SIGALRM => Ok(Some(ProcSignal::ReapChild)),
                    Signal::SIGINT => Ok(Some(ProcSignal::Reboot)),
                    _ => Ok(None),
                }
            } else {
                unimplemented!()
            }
        }
    }
}

pub enum WaitStatus {
    ContinueLoop,
    BreakDefault,
    BreakServiced,
}

pub trait ServicedInstance {
    fn wait_next_child(&self) -> WaitStatus;
}

pub struct ServicedHandle {
    #[cfg(target_os = "linux")]
    opaque: linux::OpaqueServicedHandle,
}
impl ServicedHandle {
    pub fn spawn_serviced(set: &ProcSignalInterceptor) -> Result<ServicedHandle, PrintableErrno> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                Ok(ServicedHandle {
                    opaque: linux::OpaqueServicedHandle::spawn_serviced(&set.opaque)?
                })
            } else {
                unimplemented!()
            }
        }
    }

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

pub enum ServicedInstanceGeneric {
    OpenHandle(ServicedHandle),
    Closing(ClosingServicedInstance)
}
impl ServicedInstanceGeneric {
    pub fn try_send_exit_message(&mut self) -> Result<(), PrintableErrno> {
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