//! # initd
//! Simple, serviced-compatible PID 1 implementation. **CURRENTLY IN DEVELOPMENT**
//!
//! # What?
//! initd is a simple OS userspace init implementation. Its job is to
//! perform the crucial userspace setup that is required to be done by
//! the first process (referred to as PID 1 in the *nix world), and
//! delegate any further tasks to serviced or a serviced-compatible
//! replacement.
//!
//! initd is based on [sinit](https://git.suckless.org/sinit/) (MIT),
//! which itself is based on Rich Felker's minimal init (MIT)
//! [in this EWONTFIX post](http://ewontfix.com/14/). A copy of their
//! license files are available in `LICENSE.sinit` and `LICENSE.ewontfix`
//! respectively in initd's GitHub repository.
//!
//! initd itself is licensed under the MITNFA license. See `LICENSE` on
//! initd's GitHub repository for more details.
//!
//! # Where?
//! So far initd only supports Linux systems, although if any *BSD or
//! Unix-like OS developer is interested in integrating initd and
//! serviced (or another serviced-compatible replacement) with their
//! operating system, feel free to contact me.
//!
//! Distros currently using initd: TBD.
//!
//! # Why?
//! initd was created for a lack of a proper, yet simple, Linux init
//! process focused on only performing the absolutely essential tasks
//! that PID 1 should do. At the time of this writing, systemd is the
//! dominant init implementation used by most popular Linux distributions
//! (except Android). Unfortunately, systemd suffers from noticeable
//! feature-creep, following the "everything but the kitchen sink"
//! approach for PID 1 and system/service management.
//!
//! initd strives to follow the opposite approach by doing only the bare
//! minimum (performing crucial userspace setup) and doing it well. This
//! can be seen in initd's lack of complex service dependency management,
//! networking, device hotplug management, etc. Some of those features
//! can be found in other companion projects (like serviced, which initd
//! delegates to).
//!
//! initd is written in Rust in order to reduce common bugs found in
//! projects made in non-memory-safe languages. Careful attention is made
//! to add as few dependencies as possible, with the only direct
//! dependencies being (at the time of this writing): `cfg-if`,
//! `const_format`, `cstr`, `nix`, and `precisej-printable-errno`. The low
//! dependency count helps keep third-party bugs out and compile-time low
//! (at least compared to larger Rust projects).
//!
//! # When?
//! TBD
//!
//! # How?
//! TODO
//!
//! # Who?
//! TODO
#![crate_name = "initd"]
#![cfg_attr(test, deny(warnings))]
#![deny(unused)]
#![deny(unstable_features)]
#![warn(missing_docs)]

mod platforms;

use precisej_printable_errno::{
    ExitError,
    PrintableResult,
};

use crate::platforms::{
    ProcSignal,
    ProcSignalInterceptor,
    ServicedHandle,
    ServicedInstance,
    ServicedInstanceGeneric,
    WaitStatus,
    alarm,
    initializer::{
        initial_sanity_check,
        initial_setup,
    },
    power,
};


const PROGRAM_NAME: &str = "initd";

fn main() {
    if let Err(e) = init() {
        e.eprint_and_exit()
    }
}

fn init() -> Result<(), ExitError> {
    initial_sanity_check().bail(1)?;
    initial_setup().bail(2)?;
    let signal_blocker = ProcSignalInterceptor::intercept_all().bail(3)?;
    let mut serviced = ServicedHandle::spawn_serviced(&signal_blocker).bail(4)?.to_generic();

    let mut shutdown = false;
    let mut short_alarm = false;

    loop {
        if short_alarm {
            alarm::set_short();
        } else {
            alarm::set();
        }
        let sig = match signal_blocker.wait_for_next().ok_or_eprint() {
            Some(sig) => sig,
            None => continue,
        };

        match sig {
            Some(ProcSignal::PowerOff) => {
                if !short_alarm {
                    shutdown = true;
                    short_alarm = true;
                    sig_end(&mut serviced)?;
                }
            },
            Some(ProcSignal::ReapChild) => sig_reap(&serviced, shutdown)?,
            Some(ProcSignal::Reboot) => {
                if !short_alarm {
                    short_alarm = true;
                    sig_end(&mut serviced)?;
                }
            },
            None => { /* no-op */ }
        }
    }
}

fn sig_end(serviced: &mut ServicedInstanceGeneric) -> Result<(), ExitError> {
    // send serviced end
    serviced.try_send_exit_message().bail(5)
}

fn sig_reap(serviced: &ServicedInstanceGeneric, shutdown: bool) -> Result<(), ExitError> {
    loop {
        match serviced.wait_next_child() {
            WaitStatus::ContinueLoop => { /* continue */ }
            WaitStatus::BreakDefault => break Ok(()),
            WaitStatus::BreakServiced => {
                alarm::clear();
                if shutdown {
                    break power::power_off().map(|_|()).bail(128);
                } else {
                    break power::reboot().map(|_|()).bail(127);
                }
            }
        }
    }
}