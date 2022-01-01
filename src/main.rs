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
//! If any Linux distribution maintainer/developer is exploring the use
//! of initd as their init implementation (or is already doing so), please
//! contact me to be included in this README. I am also able to give
//! recommendations on proper integration in a distribution if you contact
//! me.
//!
//! # Why?
//! At the time of this writing, systemd is the dominant init implementation
//! used by most popular Linux distributions (except Android). Unfortunately,
//! systemd suffers from noticeable feature-creep, following the "everything
//! but the kitchen sink" approach for PID 1 and system/service management.
//! initd was created for a lack of a proper, yet simple, Linux init
//! process focused on only performing the absolutely essential tasks
//! that PID 1 should do.
//!
//! initd strives to follow the Unix philosophy of
//! ["write programs that do one thing and do it well"](https://en.wikipedia.org/wiki/Unix_philosophy#Doug_McIlroy_on_Unix_programming),
//! in part by only doing the bare minimum, yet crucial, userspace setup,
//! and delegating further functions to serviced. This can be evidenced in
//! initd's lack of complex service dependency management, networking, device
//! hotplug management, etc. Some of those features can be found in other
//! companion projects (like serviced, which initd delegates execution to).
//!
//! initd is written in Rust in order to reduce common bugs found in
//! projects made in non-memory-safe languages. Careful attention is made
//! to add as few dependencies as possible, with the only direct
//! dependencies being (at the time of this writing): `cfg-if`,
//! `const_format`, `cstr`, `nix`, and `precisej-printable-errno`. The low
//! dependency count helps keep third-party bugs out and compile-time low
//! (at least compared to larger Rust projects).
//!
//! # How?
//! Every platform has different essential tasks that must be performed by the
//! first userspace process. This is explained in more detail in [platforms],
//! which also explains how initd is executed by the OS.
//!
//! # serviced?
//! serviced is a simple, yet flexible, service management system that should
//! serve as a replacement for runit/runsvdir, systemd's service management,
//! sysvinit, openrc, etc. It is so flexible that, with proper generators, it
//! could work as a drop-in replacement for *any* of the aforementioned service
//! managers!
//!
//! Unfortunately, serviced is being worked on in private for the time being.
//! Once it's sufficiently ready, it will be published and linked in this
//! README.
//!
//! **Note**: with serviced's publication will come a stable specification
//! for all communication between initd and serviced, in order to allow
//! alternative implementations of serviced-compatible programs to emerge
//! and work with stock initd, as well as initd-compatible programs able
//! to spawn and communicate properly with stock serviced. Until then,
//! anyone attempting to work on any of the two aforementioned compatible
//! programs will need to read the proper documentation as well as associated
//! source code in order to achieve compatibility. I make no guarantees as to
//! stability until the specification is published.
#![crate_name = "initd"]
#![cfg_attr(test, deny(warnings))]
#![deny(unused)]
#![deny(unstable_features)]
#![warn(missing_docs)]
#![allow(rustdoc::private_intra_doc_links)]

// Fail compilation early if incompatible features are enabled
#[cfg(all(not(debug_assertions), any(feature = "debug-notpid1")))]
compile_error!("Building release build with debug features: in order to compile a build with \
                debug-* features, you must compile without the \"--release\" flag.");

/// Every platform has different essential tasks that must be performed by the first
/// userspace process. This module contains code that calls to the specific platform
/// that the target binary is compiled to.
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


/// The program is called `initd`. The str referring to the program name is saved in
/// this constant. Useful for [PrintableResult].
const PROGRAM_NAME: &'static str = "initd";

/// The entry point of the program. This function is in charge of exiting with an error
/// code when [init] returns an [ExitError].
fn main() {
    if let Err(e) = init() {
        e.eprint_and_exit()
    }
}

/// Here is where it actually begins. This function does the following (in a
/// abstract, platform-independent manner):
/// * Performs basic sanity checks (e.g. checking whether we are the proper
///   process).
/// * Performs basic initial setup (e.g. changing to the root directory of
///   the filesystem).
/// * Tells the system to block process signals, as we will handle them
///   manually.
/// * Spawn serviced to continue initialization of services, letting it
///   handle advanced functions that are out of scope for initd.
/// * Start an event loop:
///     * Set up an alarm signal to fire after a certain amount of time, telling
///       initd to do a routine cleanup of zombie processes.
///     * Wait for the next signal (which might be triggered by an alarm).
///         * If the signal is for shutdown or reboot, tell serviced to close.
///         * If the signal is for a zombie process that must be awaited, clean it up.
///             * If the now-exited process is serviced, the system must have been signaled
///               for a reboot or a shutdown (or serviced, and therefore critical system
///               components, must have crashed, so reboot anyway). Sync any pending filesystem
///               operations and perform system shutdown or reboot as appropriate.
fn init() -> Result<(), ExitError<String>> {
    let sanity_checks = initial_sanity_check().bail(1)?;
    initial_setup(&sanity_checks).bail(2)?;
    let signal_blocker = ProcSignalInterceptor::intercept_all().bail(3)?;
    let mut serviced = ServicedHandle::spawn_serviced(&signal_blocker, sanity_checks).bail(4)?.to_generic();

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

/// Receive a signal to shutdown or reboot, so send a message to serviced that it must close.
fn sig_end(serviced: &mut ServicedInstanceGeneric) -> Result<(), ExitError<&'static str>> {
    // send serviced end
    serviced.try_send_exit_message().bail(5)
}

/// Receive a signal to perform zombie process reaping.
///
/// If the process corresponds to serviced, either it crashed or we told it to exit.
/// In any case reboot or shutdown (after syncing disks in case serviced didn't do so
/// if it crashed).
fn sig_reap(serviced: &ServicedInstanceGeneric, shutdown: bool) -> Result<(), ExitError<&'static str>> {
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