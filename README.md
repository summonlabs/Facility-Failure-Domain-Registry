# Facility Failure Domain Registry

Canonical physical failure-domain authority.

It answers one question, and answers it the same way every time:

> Which physical facility resources share a failure fate, under which declared
> domain relationships and generation, and which higher-layer decisions may rely
> on that failure-domain model?

The library owns stable failure-domain identities, typed domain classes,
explicit membership of opaque external resource identities, nested and
overlapping relationships where they are legal, shared-fate relationships,
inter-domain dependency edges, declared independence, lifecycle, provenance,
generation-bound immutable snapshots, conflict preservation and stale-generation
rejection.

It is a portable C++20 CMake library with no third-party dependencies: SHA-256
(FIPS 180-4), the canonical serialization format, every identity, generation,
epoch and incarnation type, and the durable store are implemented in this
repository.

## Systems boundary

**Owned here**

* stable failure-domain identity assignment and refusal of identity reuse;
* typed domain classes (power source/distribution, cooling source/distribution,
  room, hall, row, rack, shared service, composite);
* explicit membership of resources owned by other authorities;
* containment (nesting), overlap as a derived reporting concept, dependency
  edges, shared-fate relationships, declared independence, external aliases;
* lifecycle (active, retired, superseded) and replacement links;
* provenance for every declared fact, retained forever;
* authoritative generations with a content digest and an exact model binding;
* deterministic resolution of contradictory claims, with conflicts preserved;
* stale-generation rejection and stale-writer fencing.

**Not owned here**

Facility topology, electrical and cooling topology or actuation, rack occupancy,
asset lifecycle, incident lifecycle, degraded-mode policy, recovery execution,
workload scheduling and placement, DFI path failure domains, and ASI execution
failure domains. Those objects are referenced only through opaque identities
(`AuthorityId` + `ResourceId`); their bytes are preserved exactly and are never
resolved, normalized or interpreted.

Nothing in this library reads a sensor, contacts a BMS/DCIM, actuates a PDU, UPS,
generator or cooling device, or observes whether equipment is running. It stores
declare relationships and answers questions about them.

## Model

### Identities

* `DomainId` is assigned by the registry, monotonic, and never reused. A
  requested identity that was already issued is refused (`duplicate_identity`),
  including an identity below the issued high-water mark that was never
  materialized.
* A domain also has a natural key: the pair (domain class, natural key) is unique
  for the lifetime of a store, including after retirement, so a name can never
  silently change meaning.
* External identities are opaque: `ExternalRef { AuthorityId, ResourceId }`.

### Claims

Every statement about the facility is an append-only **claim** (a fact). Nothing
is edited or deleted; revocation adds evidence instead of removing it.

| Claim | Meaning |
| --- | --- |
| `membership` | the subject domain covers an external resource |
| `containment` | the subject physically nests the object |
| `dependency` | the subject depends on the object, or on an external target |
| `shared_fate` | the subject and object share a failure fate (symmetric) |
| `independence` | the subject and object are declared diverse (symmetric) |
| `supersession` | the subject is superseded by the object |
| `retirement` | the subject is retired |
| `external_alias` | the subject domain *is* an external identity |
| `retraction` | the declaring authority disputes another authority's claim |

Every claim carries provenance: the declaring authority, that authority's own
revision counter, and optional evidence text.

### Evidence resolution

Each claim slot (claim kind plus endpoints) is resolved independently:

1. Within one authority, the highest `authority_revision` wins; older claims are
   retained as `superseded_revision` evidence.
2. Across authorities, the highest declared precedence wins. Authorities that are
   not in the precedence table have precedence 1, so declarations from different
   authorities are equal by default. Lower-precedence claims are retained as
   `outranked` evidence.
3. An authority may retract a claim of any authority. A retraction takes effect
   only when the retracting authority has strictly higher precedence than the
   disputed authority. Equal precedence is a contradiction, and a contradiction
   is **preserved**: both sides are reported as `conflicting`, and the slot does
   not silently resolve to either. Raising the retractor's precedence with an
   explicit policy declaration resolves it deterministically.
4. A domain claimed superseded by more than one successor at the same precedence
   keeps its conflict and is not treated as superseded.
5. External dependencies resolve through `external_alias` claims: exactly one
   active alias resolves the reference; none leaves it unresolved
   (`no_alias`); more than one is ambiguous and reported as a conflict. Nothing
   is guessed.

## Failure semantics

The resolved model is a directed **exposure graph** over *active* domains:

| Resolved claim | Exposure edges |
| --- | --- |
| `containment A B` | A → B (a failing enclosure exposes what it encloses) |
| `dependency A B` | B → A (a failing dependency exposes its dependent) |
| `shared_fate A B` | A → B and B → A |
| `independence` | none (a claim, not an edge) |
| `supersession`, `retirement` | none (lifecycle only) |

From that graph:

* **Upstream exposure** of *X*: every domain whose failure reaches *X*.
* **Downstream exposure** of *X*: everything *X*'s failure reaches.
* **Common exposers** of a set: domains whose failure exposes every member (the
  single points of failure for that set).
* **Blast radius** of a set: the union of what any member exposes.
* **Shared fate** between *X* and *Y* is proven exactly when they are mutually
  reachable — the same strongly connected component. One-way containment is not
  shared fate, and neither is co-location.
* **Shared-fate strength** is the highest precedence threshold at which that
  mutual reachability still holds (a max-min bottleneck over the cycle).
* **Pair verdict** combines a shared-fate proof with an independence claim:
  strictly stronger precedence wins, equal precedence is `conflicting`, and
  neither is `unknown`.

Unknown is not independence. A pair with no proof and no declaration answers
`unknown`, and independence is never inherited through containment or
dependency.

### Lifecycle

Retirement and supersession are claims, so they are provenance-bearing and
retractable. Only active domains participate in current exposure answers;
retired and superseded domains remain queryable history. A supersession link is a
lifecycle statement, not an exposure edge: a replacement does **not** inherit its
predecessor's memberships, dependencies or shared fate. Consumers must re-declare
them, which is the point — a replacement is a new physical thing.

## Queries

All queries are const methods on `ffd::Snapshot`, an immutable,
digest-bound view. They take no locks and are safe for concurrent use.

~~~cpp
std::uint64_t generation() const;              // authoritative generation
const Digest& digest() const;                  // content digest of that generation
ModelBinding binding() const;                  // {generation, digest}
Status verify_binding(const ModelBinding&) const;  // stale_generation / model_mismatch

Result<DomainInfo> domain(DomainId) const;
Result<std::vector<DomainInfo>> domains(bool include_inactive) const;
Result<std::vector<MembershipInfo>> memberships(DomainId) const;

Result<std::vector<DomainId>> containing_domains(const ExternalRef&, bool include_inactive) const;
Result<std::vector<DomainId>> enclosing_domains(const ExternalRef&, bool include_inactive) const;
Result<std::vector<DomainId>> domains_for_reference(const ExternalRef&) const;

Result<std::vector<DomainId>> upstream_exposure(DomainId, ExposureOptions = {}) const;
Result<std::vector<DomainId>> downstream_exposure(DomainId, ExposureOptions = {}) const;
Result<std::vector<DomainId>> common_exposers(const std::vector<DomainId>&, ExposureOptions = {}) const;
Result<std::vector<DomainId>> blast_radius(const std::vector<DomainId>&, ExposureOptions = {}) const;
Result<std::vector<ExternalRef>> jointly_exposed_resources(const std::vector<ExternalRef>&) const;

Result<std::vector<DomainId>> shared_fate_group(DomainId) const;
Result<std::vector<DomainId>> successors(DomainId) const;
Result<PairVerdictResult> pair_verdict(DomainId, DomainId) const;

Result<std::vector<FactEvidence>> evidence_for(const ClaimRef&) const;
Result<std::vector<ConflictInfo>> conflicts() const;
Result<std::vector<UnresolvedReference>> unresolved_references() const;
std::string canonical_text() const;            // deterministic rendering
~~~

Results are ordered by stable identity (ascending `DomainId`, then authority and
resource id for external references), never by container or thread timing.
`containing_domains` reports explicit membership; `enclosing_domains` reports the
containment ancestors of those domains. The two are deliberately separate
answers.

`memberships` and `evidence_for` expose the full evidence list behind an answer,
including `outranked`, `superseded_revision` and `conflicting` entries, so a
downstream decision can cite exactly what supports it.

## Determinism and the content digest

The model content is serialized canonically: fixed-width little-endian fields,
length-prefixed strings, domains in identity order, claims in a defined total
order (kind, endpoints, authority, revision, evidence), and no registry-local
handles. The digest is SHA-256 over exactly those bytes.

Consequences that the test suite proves:

* the same declarations in a different order produce the same digest;
* reloading a durable generation reproduces the same digest;
* the digest never depends on wall-clock time, addresses, process identity or
  hash-map iteration order.

Session-local fact handles are deliberately absent from the digest, so a model's
identity is its content.

## Durable store

Three files, all derived from the configured store path:

| File | Contents |
| --- | --- |
| `<store>` | header (magic, format version, generation, writer epoch, payload length, content digest) + canonical payload + SHA-256 trailer |
| `<store>.epoch` | epoch record: epoch, last durable generation, own SHA-256 trailer |
| `<store>.lock` | empty; the kernel-owned exclusive lock lives here |

**Publication.** With `Durability::DurablePerMutation` (the default) every
successful mutation is committed before the call returns: the whole generation is
staged to a temporary file in the same directory, flushed, read back and verified
byte for byte, then atomically replaced (`MoveFileEx` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`); the epoch record is
published with the same staged, verified, atomic discipline, so a crash cannot
leave a torn epoch behind either. With `Durability::ExplicitPublish` mutations advance the
in-memory generation only and `publish()` commits; uncommitted state is discarded
on close and is never half-written.

**Strict decode.** Reads verify magic, format version, header length, declared
payload length, the file trailer digest, the payload version, every record's
internal consistency, and that the decoded content re-derives the header's
content digest. Ambiguous, corrupt, truncated or partially published state is
refused rather than repaired.

**Writer exclusion and fencing.** Mutation authority is a kernel-owned exclusive
lock on `<store>.lock`, opened, locked and held for the lifetime of the writer.
The lock is released by the operating system when the process dies, so an abrupt
death never leaves a stuck store. Every open increments the durable epoch, and
every publication re-reads the epoch record first: a writer whose epoch has moved
(in an administrative takeover or a restore) is refused with `fenced` instead of
overwriting a newer generation.

**Rollback detection.** A store file whose generation is behind the epoch
record's high-water mark is refused with `rollback_detected`, for writers and for
read-only consumers.

**Recovery.** Recovery is conservative: the reopened model is one whole
generation, either the last committed one or the one being committed when the
process died. Stale staged files are ignored and removed by the next writer.
There is no partial generation, no merge and no repair heuristic.

**Readers.** `load_snapshot` does not take the writer lock and does not create or
modify anything. It enforces rollback detection when it can take a consistent
view of the epoch record, and otherwise binds to the published generation.

## Concurrency model

* `Registry` is the single writer. Every public entry point takes exactly one
  internal mutex, releases it before returning, and never calls another locked
  entry point.
* There are no callbacks, no events, no worker threads and no nested lock
  acquisition anywhere in the library, so lock re-entry, lock inversion,
  call-out-under-lock and shutdown-under-lock defects are structurally absent.
* Mutations are applied to the authoritative state in place and rolled back
  unless the result resolves into a valid model and is durably published.
* `Snapshot` is immutable and shared by value; concurrent readers never observe a
  later mutation, and a snapshot copy keeps its generation alive independently of
  the registry.
* The durable layer owns no in-process locks; the only lock is the kernel file
  lock described above.

### Locking and lifetime audit

The call paths and ownership were audited by hand, not only by tests:

* **Read→write reacquisition / write-lock re-entry.** `Registry` owns exactly one
  non-recursive mutex. It is taken at the public entry point and nowhere else;
  every internal helper is a method of the implementation object and takes its
  arguments explicitly, so no helper can reacquire it. Queries never touch the
  registry lock because they run on `Snapshot`.
* **Call-outs while a lock is held.** The library has no callbacks, no events and
  no observer hooks. The one function called from inside a locked publication
  path is the test-only crash-injection hook, which reads one atomic and
  terminates the process; it is compiled out unless
  `FFD_ENABLE_CRASH_INJECTION` is defined and never calls back into the library.
* **Nested acquisition and ordering.** The only OS resources are file handles.
  The writer lock is acquired first and held for the store's lifetime; data
  handles (epoch record, staged file, read-back) are opened, used and closed
  individually, and no second handle is ever held while acquiring the lock, so
  there is no inversion and no ordering ambiguity.
* **Joining workers and shutdown.** The library starts no threads, and its
  destructor only releases the kernel lock; nothing waits on work that needs the
  same lock.
* **Lifetime of views.** A `Snapshot` is a value holding an immutable
  `shared_ptr` payload, so a snapshot cannot outlive or observe republished
  state. Reading a value out of a temporary `Result` returns the value itself,
  not a reference into the temporary: an earlier revision returned an rvalue
  reference there, which let a ranged loop over `conflicts().value()` read freed
  memory. That defect was found during the adversarial pass and fixed in the API;
  the callers were corrected with it.

## Error model

Failures are returned as `Result<T>` / `Status` with a stable code and a
human-readable detail; no exception is thrown across the API boundary for
expected conditions.

`invalid_argument`, `limit_exceeded`, `duplicate_natural_key`,
`duplicate_identity`, `duplicate_claim`, `unknown_domain`, `unknown_fact`,
`domain_not_active`, `already_retired`, `cycle_not_allowed`, `self_reference`,
`stale_generation`, `model_mismatch`, `idempotency_key_reuse`,
`idempotency_key_required`, `writer_lock_unavailable`, `fenced`,
`rollback_detected`, `corrupt_state`, `unsupported_format_version`,
`truncated_state`, `digest_mismatch`, `read_only`, `storage_io`, `overflow`,
`not_found`.

Externally influenced quantities (identities, generations, sequence numbers,
counts, lengths, precedence values, epochs) are bounded and computed with checked
arithmetic; overflow is refused, never wrapped.

## Idempotency

Mutations carry an idempotency key by default (`MutationKeyPolicy::Required`).
The registry fingerprints the requested effect — deliberately excluding the
precondition — and records the outcome durably. A retry of the same operation
returns the recorded outcome and changes nothing, even when the caller's expected
generation is now stale, so a lost response cannot cause a second consequential
mutation. Reusing a key for a different request is refused
(`idempotency_key_reuse`). The journal is bounded by
`Limits::max_idempotency_entries`; when it is full the oldest entry is evicted, so
replay protection covers the retained window and that limit is explicit rather
than silent.

## Building

~~~sh
cmake -S . -B build -DFFD_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
~~~

Requirements: CMake 3.21 or newer and a C++20 compiler (MSVC 19.30+, GCC 11+ or
Clang 14+). Options: `FFD_BUILD_TESTS`, `FFD_BUILD_BENCHMARKS`,
`FFD_WARNINGS_AS_ERRORS` (default ON), `FFD_ENABLE_ASAN`,
`FFD_ENABLE_CRASH_INJECTION` (test-only crash injection points, default OFF).

## Installing and consuming

~~~sh
cmake --install build --config Release --prefix /some/clean/prefix
~~~

~~~cmake
find_package(FacilityFailureDomainRegistry 1.0 REQUIRED)
target_link_libraries(your_target PRIVATE FFD::ffd)
~~~

`tests/consumer` is an independent out-of-tree project that consumes the
installed package this way. It writes a generation, binds to it, reloads it from
disk, verifies the binding, and proves that a later generation makes the earlier
binding explicitly stale.

## Using the library

~~~cpp
#include "ffd/registry.hpp"

ffd::StoreConfig config;
config.path = "facility.ffdr";                  // <store>, <store>.epoch, <store>.lock
config.durability = ffd::Durability::DurablePerMutation;

auto registry = ffd::Registry::open(config);
if (!registry.ok()) { /* writer_lock_unavailable, rollback_detected, ... */ }

ffd::CreateDomainRequest room;
room.context.provenance.authority.value = "dccp.topology";
room.context.key = ffd::IdempotencyKey{room.context.provenance.authority, "room-1"};
room.domain_class = ffd::DomainClass::Room;
room.natural_key = "room-1";
const auto created = registry.value()->create_domain(room);

ffd::DeclareContainmentRequest nesting;
nesting.context = room.context;
nesting.parent = created.value().domain;
nesting.child = rack_id;
registry.value()->declare_containment(nesting);

// A downstream decision binds to one exact generation.
const ffd::ModelBinding binding = registry.value()->snapshot().binding();
const auto exposed = registry.value()->snapshot().downstream_exposure(pdu_id);
~~~

## Validation performed

All of the following ran on Windows 11 x64 with MSVC 19.44 (Visual Studio 2022),
CMake 4.3, Release and Debug configurations, with `/W4 /WX /permissive-` and zero
first-party warnings.

**Test suite** (9 executables, all passing):

| Executable | What it proves |
| --- | --- |
| `ffd_test_types` | SHA-256 against published vectors, digest encoding, enum and slug stability, UTF-8 rejection, checked arithmetic, limits |
| `ffd_test_model` | identity assignment and refusal of reuse, duplicate natural keys, duplicate claims, explicit membership, containment vs membership, cycle refusal, shared-fate transitivity, mutual dependency, independence vs shared fate, precedence resolution, retirement, supersession, competing successors, alias resolution and ambiguity, retraction precedence, generations and bindings, deep and wide graphs |
| `ffd_test_query` | common exposers, blast radius, upstream/downstream chains, jointly exposed resources, shared-fate groups, ordering and completeness of diagnostics, digest independence from declaration order, evidence statuses |
| `ffd_test_storage` | durable round trip across handles, readers without the writer lock, byte-for-byte corruption detection at every offset, truncation detection at every length, trailing-byte refusal, rollback detection, epoch-record corruption, staged-file cleanup, explicit publish, limits, device names, long paths, relative paths |
| `ffd_test_determinism` | replay returns the recorded outcome, replay survives restart and outranks a stale precondition, key reuse refusal, content-not-order digests, reload stability, journal eviction, stable ordering |
| `ffd_test_adversarial` | malformed identities and UTF-8, self references, long cycles, an absurd-but-bounded wide star and deep chain, identity-space exhaustion, repeated open/close, concurrent mutation and concurrent reads, unwritable destinations, oversized files, absurd declared lengths, identity reuse after retirement |
| `ffd_test_property` | randomized state machines compared against an independently written reference model (dense matrices, exhaustive thresholds, brute-force closures) over domains, membership, nesting, dependencies, shared fate, independence, retirement, replacement, precedence and revocation — every published answer compared after every operation |
| `ffd_test_multiprocess` | real independent processes: a second writer is refused, a reader process sees the published generation, abrupt death releases the kernel lock and the successor's epoch is strictly greater, crash injection at each durable-publication boundary recovers to a whole generation whose digest matches a replay, external kill during publication recovers, and a writer whose epoch was superseded is fenced |
| `ffd_test_lifecycle` | a full facility model end to end: exposure answers, jointly exposed assets, durability across processes, a downstream binding that detects staleness, replacement semantics, replay across restart, canonical rendering stability |

**Randomized and property results.** Five seeds (three general, two
conflict-heavy) × 260 operations each, with the reference model re-derived from
the claims independently of the library. Every operation compares domain set,
lifecycle, fact count, generation, upstream and downstream exposure, shared-fate
groups, pair verdicts (exhaustively for small models), containing domains and the
predicted accept/refuse decision including the exact error code. Seeds are
printed on failure together with the operation index.

**Multiprocess proofs.** All of the above child processes are real OS processes
started with `CreateProcess`; crash injection terminates the process silently at
the boundary under test (`TerminateProcess`), never through a caught exception or
a serialization-only rehearsal. A second process is refused while the first holds
the store, and after abrupt death the successor opens with a strictly greater
epoch and sees a whole generation.

**AddressSanitizer.** A dedicated `/fsanitize=address` build
(`-DFFD_ENABLE_ASAN=ON`) is configured and the complete suite runs under it with
the MSVC ASan runtime; the results are reported separately from the Release run.

**Benchmarks.** `ffd_bench_registry` measures completed useful operations, not
submission latency. Its output states the workload scale and whether each number
is REAL (the operation really ran against this machine's filesystem, including
the durability cost claimed for it) or SYNTHETIC (a generated facility graph in
memory). Indicative measurements from the development machine, Release build:

| Operation | Rate | Scale | Provenance |
| --- | --- | --- | --- |
| domain creation, in-memory generation | 384 /s | 5 000 domains, one store | SYNTHETIC |
| domain creation, durable publication | 70 /s | 500 domains, one store | REAL |
| store open + strict decode | 948 /s | 500-domain generation, 78 KB | REAL |
| upstream exposure query | 3 259 /s | 2 000 domains, 1 992 edges | SYNTHETIC graph, real query |
| pair failure-fate verdict | 3 001 /s | 2 000 domains | SYNTHETIC graph, real query |

The difference between the first two rows is the honest cost of the durability
claim: with `DurablePerMutation` every mutation writes, flushes, verifies and
atomically replaces the whole generation, so mutation cost is proportional to
model size. That is the price of immutable generation-bound snapshots and it is
measured rather than hidden.

## REAL, SYNTHETIC and UNSUPPORTED

* **REAL** — durable publication, atomic replacement, kernel file locking,
  rollback detection, multi-process exclusion, crash recovery, package install,
  and downstream consumption all really run against the host operating system,
  filesystem and processes in the test suite.
* **SYNTHETIC** — every facility, electrical, cooling, rack, asset and service
  identity in the tests and benchmarks is generated test data. The library has
  never been run against real facility hardware, a BMS, DCIM, PDU, UPS,
  generator, cooling plant or network device, and it never will be at this
  boundary: it does not talk to them.
* **UNSUPPORTED** — there is no BMS/DCIM integration, no device or vendor SDK
  integration, no sensor ingestion, no live facility observation, no
  RDMA/InfiniBand/NVLink or accelerator hardware involvement, and no multi-host
  operation. There are no performance claims for hardware this library never
  touches.
* **Toolchains.** MSVC 19.44 on Windows x64 is the only toolchain on which this
  repository has been built, tested and packaged. The CMake project carries
  GCC/Clang warning flags and the durable layer has no POSIX implementation, so a
  GCC or Clang build is neither claimed nor validated here. The model, resolution
  and query layers are standard C++20, but that is a portability expectation, not
  a tested result.

## Limitations

* Mutation cost is proportional to model size: every mutation resolves the whole
  model and, when durable, republishes the whole generation. Models are sized for
  tens of thousands of domains, not millions.
* The idempotency journal is bounded; replay protection covers the retained
  window, and eviction is explicit.
* `Durability::ExplicitPublish` deliberately discards uncommitted state on close.
* Conflicts are reported, never resolved automatically: a consumer that needs one
  answer must declare precedence or retract a claim.
* Precedence is administrator-declared policy, applied as an ordered operation;
  it is not itself a resolved claim.
* Fact handles are session-local; durable references to a claim use `ClaimRef`.

## Repository layout

~~~
include/ffd/     public headers (types, registry, snapshot, store, version)
src/             implementation (canonical encoding, resolution, queries, storage)
tests/           test suite, helper process, out-of-tree consumer
bench/           benchmarks
cmake/           package configuration template
~~~

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
