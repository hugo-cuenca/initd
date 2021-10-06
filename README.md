# initd

Simple, serviced-compatible PID 1 implementation. **CURRENTLY IN DEVELOPMENT**

## What?
initd is a simple OS userspace init implementation. Its job is to
perform the crucial userspace setup that is required to be done by
the first process (referred to as PID 1 in the *nix world), and
delegate any further tasks to serviced or a serviced-compatible
replacement.

initd is based on [sinit](https://git.suckless.org/sinit/) (MIT),
which itself is based on Rich Felker's minimal init (MIT)
[in this EWONTFIX post](http://ewontfix.com/14/). A copy of their
license files are available in `LICENSE.sinit` and `LICENSE.ewontfix`
respectively in initd's GitHub repository.

initd itself is licensed under the MITNFA license. See `LICENSE` on
initd's GitHub repository for more details.

## Where?
So far initd only supports Linux systems, although if any *BSD or
Unix-like OS developer is interested in integrating initd and
serviced (or another serviced-compatible replacement) with their
operating system, feel free to contact me.

If any Linux distribution maintainer/developer is exploring the use
of initd as their init implementation (or is already doing so), please
contact me to be included in this README. I am also able to give
recommendations on proper integration in a distribution if you contact
me.

## Why?
At the time of this writing, systemd is the dominant init implementation
used by most popular Linux distributions (except Android). Unfortunately,
systemd suffers from noticeable feature-creep, following the "everything
but the kitchen sink" approach for PID 1 and system/service management.
initd was created for a lack of a proper, yet simple, Linux init
process focused on only performing the absolutely essential tasks
that PID 1 should do.

initd strives to follow the Unix philosophy of
["write programs that do one thing and do it well"](https://en.wikipedia.org/wiki/Unix_philosophy#Doug_McIlroy_on_Unix_programming),
in part by only doing the bare minimum, yet crucial, userspace setup,
and delegating further functions to serviced. This can be evidenced in
initd's lack of complex service dependency management, networking, device
hotplug management, etc. Some of those features can be found in other
companion projects (like serviced, which initd delegates execution to).

initd is written in Rust in order to reduce common bugs found in
projects made in non-memory-safe languages. Careful attention is made
to add as few dependencies as possible, with the only direct
dependencies being (at the time of this writing): `cfg-if`,
`const_format`, `cstr`, `nix`, and `precisej-printable-errno`. The low
dependency count helps keep third-party bugs out and compile-time low
(at least compared to larger Rust projects).

## How?
Every platform has different essential tasks that must be performed by the
first userspace process. This is explained in more detail in [platforms],
which also explains how initd is executed by the OS.

## serviced?
serviced is a simple, yet flexible, service management system that should
serve as a replacement for runit/runsvdir, systemd's service management,
sysvinit, openrc, etc. It is so flexible that, with proper generators, it
could work as a drop-in replacement for *any* of the aforementioned service
managers!

Unfortunately, serviced is being worked on in private for the time being.
Once it's sufficiently ready, it will be published and linked in this
README.

**Note**: with serviced's publication will come a stable specification
for all communication between initd and serviced, in order to allow
alternative implementations of serviced-compatible programs to emerge
and work with stock initd, as well as initd-compatible programs able
to spawn and communicate properly with stock serviced. Until then,
anyone attempting to work on any of the two aforementioned compatible
programs will need to read the proper documentation as well as associated
source code in order to achieve compatibility. I make no guarantees as to
stability until the specification is published.

License: MITNFA
