# Contributing to Facility Failure Domain Registry

Facility Failure Domain Registry is DCCP boundary 49 and is maintained by Summon
Software Labs.

## Licensing of contributions

This project is licensed under the Apache License, Version 2.0 (see `LICENSE`).

By submitting a contribution you agree that it is licensed under the terms of
that license, as described in section 5 of the license text. There is **no
Contributor License Agreement** to sign and no copyright assignment is required:
you keep the copyright in your contribution and grant the project the license
described in `LICENSE`.

Please do not add co-author trailers or attribution lines that name tools,
assistants or intermediate processes; commit authorship is the responsibility of
the human contributor.

## What belongs in this repository

This project owns the canonical physical failure-domain authority for a facility:
stable failure-domain identities, typed domain classes, explicit membership of
opaque external resource identities, containment and overlap relationships,
shared-fate relationships, inter-domain dependency edges, declared independence,
lifecycle transitions, provenance, generation-bound immutable snapshots,
deterministic resolution of conflicting claims, and stale-generation rejection.

It deliberately does **not** own, and must not grow:

* facility or electrical/cooling topology and its actuation (Topology, Power
  Topology, Cooling Topology, PDU Control, UPS Control);
* rack occupancy and placement (Rack Occupancy, Facility Placement Planner);
* asset identity and lifecycle (Asset Registry, Asset Lifecycle);
* incident lifecycle and degraded-mode policy (Incident Manager, Degraded
  Operation Manager);
* recovery execution (Recovery Manager, Cooling Failover);
* workload scheduling and placement (Scheduler, Placement);
* DFI path failure domains (Dependency Fabric, Path Failure Domain);
* ASI execution failure domains (Execution Boundary, ASI Runtime).

Those objects are referenced only through opaque identities (`AuthorityId` and
`ResourceId`). Those bytes are preserved exactly and are never resolved,
normalized or interpreted here.

Shared fate is never inferred from labels, proximity, rack membership, common
feed names, cooling-loop names or topology. Membership, containment, dependency,
shared fate and independence are explicit declarations; a plausible-looking
inference is a defect, not a feature.

## Building and testing

The project is a portable C++20 CMake project with no third-party dependencies:

```sh
cmake -S . -B build -DFFD_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Requirements: CMake 3.21 or newer and a C++20 compiler (MSVC 19.30+, GCC 11+ or
Clang 14+).

Useful options:

* `-DFFD_WARNINGS_AS_ERRORS=ON` (default) - first-party warnings are errors; do
  not add warning suppressions, fix the cause;
* `-DFFD_ENABLE_ASAN=ON` - AddressSanitizer build;
* `-DFFD_ENABLE_CRASH_INJECTION=ON` - compiles the deterministic
  durable-publication crash injection points used by the crash-recovery proofs;
* `-DFFD_BUILD_TESTS` and `-DFFD_BUILD_BENCHMARKS` - optional components, both
  off by default when the library is embedded.

Tests are plain executables registered with CTest and they run to completion. A
test that does not finish is a defect to diagnose and repair, not something to
terminate and call a pass.

Randomized and property tests derive their workload from a printed seed; a
failure reports the seed and the operation index, and the same executable can be
re-run with a test-name filter to reproduce it exactly. Never weaken a case to
make a build pass.

## Code quality expectations

* C++20, standard library only. A new third-party dependency must be justified in
  the pull request, packaged and validated; the default answer is no.
* The public headers are a long-lived contract: add, do not renumber. Error codes,
  enumerators and durable format fields are stable once released.
* Every mutation states the authority and the base generation it was planned
  against, and must refuse stale authority rather than merge it.
* Deterministic outcomes only: no wall-clock values, no randomness, no
  process-specific values and no unordered iteration order in canonical content.
* Bound every externally influenced size before allocation, and use checked
  arithmetic for authoritative counters, identities and generations.
* Keep the library's locking story explicit: one mutex at the public entry
  points, no call-outs while a lock is held, no lock re-entry, no worker threads
  and no callbacks.
* Keep the claim boundary explicit in the API and in the documentation: this
  project answers failure-domain questions and never claims operating state,
  health, actuation authority or recovery execution.

## Before opening a pull request

1. `cmake --build build --config Release` and `--config Debug` are warning-free
   with warnings-as-errors enabled.
2. The full test suite passes, including the proof obligations your change adds.
3. `cmake --install` plus the out-of-tree `find_package` consumer in
   `tests/consumer` still works when you changed anything public.
4. `README.md` describes only implemented and verified behaviour.
