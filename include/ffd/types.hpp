// Facility Failure Domain Registry - DCCP boundary 49.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ffd {

// ---------------------------------------------------------------------------
// Content digest (SHA-256 over the canonical model encoding)
// ---------------------------------------------------------------------------
inline constexpr std::size_t kDigestBytes = 32;

struct Digest {
  std::array<std::uint8_t, kDigestBytes> bytes{};

  friend bool operator==(const Digest&, const Digest&) = default;

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string hex() const;
  [[nodiscard]] static std::optional<Digest> from_hex(std::string_view text);
};

// ---------------------------------------------------------------------------
// Stable failure-domain identity
// ---------------------------------------------------------------------------
// Registry-assigned, monotonic and never reused: identity reuse is refused
// rather than repaired. Value 0 is the invalid/absent identity.
struct DomainId {
  std::uint64_t value{0};

  friend bool operator==(const DomainId&, const DomainId&) = default;
  friend auto operator<=>(const DomainId&, const DomainId&) = default;

  [[nodiscard]] bool valid() const noexcept { return value != 0; }
};

// Typed domain class. Unknown wire values are rejected by strict decoding; the
// class is a declared attribute and is never used to infer failure fate.
enum class DomainClass : std::uint16_t {
  PowerSource = 1,
  PowerDistribution = 2,
  CoolingSource = 3,
  CoolingDistribution = 4,
  Room = 5,
  Hall = 6,
  Row = 7,
  Rack = 8,
  SharedService = 9,
  Composite = 10,
};

[[nodiscard]] const char* to_string(DomainClass value) noexcept;
[[nodiscard]] std::optional<DomainClass> domain_class_from_string(std::string_view text) noexcept;
[[nodiscard]] bool is_known_domain_class(std::uint16_t raw) noexcept;

// Lifecycle of a failure domain. Only Active domains participate in current
// failure-exposure answers; Retired and Superseded domains are retained as
// historical, provenance-bearing records.
enum class DomainLifecycle : std::uint8_t {
  Active = 1,
  Retired = 2,
  Superseded = 3,
};

[[nodiscard]] const char* to_string(DomainLifecycle value) noexcept;

// ---------------------------------------------------------------------------
// Opaque external identities
// ---------------------------------------------------------------------------
// Bounded, validated opaque tokens. The registry never interprets them.
struct AuthorityId {
  std::string value;

  friend bool operator==(const AuthorityId&, const AuthorityId&) = default;
  friend auto operator<=>(const AuthorityId&, const AuthorityId&) = default;

  [[nodiscard]] bool empty() const noexcept { return value.empty(); }
};

struct ResourceId {
  std::string value;

  friend bool operator==(const ResourceId&, const ResourceId&) = default;
  friend auto operator<=>(const ResourceId&, const ResourceId&) = default;

  [[nodiscard]] bool empty() const noexcept { return value.empty(); }
};

// An identity owned by another authority (asset registry, topology service, DFI
// path model, ASI execution model, ...). Referenced, never interpreted.
struct ExternalRef {
  AuthorityId authority;
  ResourceId resource;

  friend bool operator==(const ExternalRef&, const ExternalRef&) = default;
  friend auto operator<=>(const ExternalRef&, const ExternalRef&) = default;

  [[nodiscard]] bool empty() const noexcept { return authority.empty() || resource.empty(); }
};

// Natural key of a domain: unique for the lifetime of a store.
struct DomainKey {
  DomainClass domain_class{DomainClass::Composite};
  std::string natural_key;

  friend bool operator==(const DomainKey&, const DomainKey&) = default;
  friend auto operator<=>(const DomainKey&, const DomainKey&) = default;
};

// ---------------------------------------------------------------------------
// Provenance, idempotency, bindings
// ---------------------------------------------------------------------------
struct Provenance {
  AuthorityId authority;               // required
  std::uint64_t authority_revision{};  // revision counter owned by that authority
  std::string evidence;                // optional citation
};

struct IdempotencyKey {
  AuthorityId authority;  // required
  std::string value;      // required

  friend bool operator==(const IdempotencyKey&, const IdempotencyKey&) = default;
  friend auto operator<=>(const IdempotencyKey&, const IdempotencyKey&) = default;
};

struct MutationContext {
  Provenance provenance;
  // Optimistic-concurrency precondition. 0 means "no precondition".
  std::uint64_t expected_generation{0};
  // At-most-once token; required unless the store accepts keyless mutations.
  std::optional<IdempotencyKey> key;
};

// An exact model binding handed to downstream consumers.
struct ModelBinding {
  std::uint64_t generation{0};
  Digest digest{};

  friend bool operator==(const ModelBinding&, const ModelBinding&) = default;
};

// ---------------------------------------------------------------------------
// Declared relationships
// ---------------------------------------------------------------------------
enum class FactKind : std::uint16_t {
  Membership = 1,     // subject domain covers an external resource
  Containment = 2,    // subject physically nests object
  Dependency = 3,     // subject depends on object or on an external target
  SharedFate = 4,     // subject and object share a failure fate (symmetric)
  Independence = 5,   // subject and object are declared diverse (symmetric)
  Supersession = 6,   // subject is superseded by object
  Retirement = 7,     // subject is retired
  Retraction = 8,     // retracts claims of a target authority on one slot
  ExternalAlias = 9,  // subject domain is the external object
};

[[nodiscard]] const char* to_string(FactKind value) noexcept;
[[nodiscard]] bool is_known_fact_kind(std::uint16_t raw) noexcept;
// True for kinds whose claim slot is unordered in (subject, object).
[[nodiscard]] bool is_symmetric_fact_kind(FactKind value) noexcept;
// True for kinds that carry an external reference instead of a domain object.
[[nodiscard]] bool is_external_fact_kind(FactKind value) noexcept;

// Status of one piece of evidence in the resolved model.
enum class FactStatus : std::uint8_t {
  Effective = 1,           // participates in the published generation
  SupersededRevision = 2,  // same authority, older authority_revision
  Outranked = 3,           // lower-precedence authority
  Conflicting = 4,         // equal-precedence contradiction
};

[[nodiscard]] const char* to_string(FactStatus value) noexcept;

// Identifies a claim slot without depending on session-local fact handles.
struct ClaimRef {
  FactKind kind{FactKind::Membership};
  FactKind target_kind{FactKind::Membership};  // set for Retraction only
  DomainId subject;
  DomainId object;               // invalid for external kinds
  ExternalRef external;          // set for external kinds
  AuthorityId target_authority;  // set for Retraction only

  friend bool operator==(const ClaimRef&, const ClaimRef&) = default;
};

// One piece of evidence behind a query answer. Evidence is never discarded:
// outranked, superseded and conflicting claims remain readable.
struct FactEvidence {
  FactKind kind{FactKind::Membership};
  DomainId subject;
  DomainId object;
  ExternalRef external;
  AuthorityId target_authority;
  AuthorityId authority;
  std::uint64_t authority_revision{};
  std::string evidence;
  FactStatus status{FactStatus::Effective};
  std::uint32_t precedence{};
};

// ---------------------------------------------------------------------------
// Errors and result plumbing
// ---------------------------------------------------------------------------
enum class ErrorCode : std::uint16_t {
  Ok = 0,
  InvalidArgument = 1,       // malformed, out of range, or structurally illegal input
  LimitExceeded = 2,         // configured limit or representable range exhausted
  DuplicateNaturalKey = 3,   // (class, natural key) already used in this store
  DuplicateIdentity = 4,     // requested DomainId already issued
  DuplicateClaim = 5,        // identical claim from the same authority and revision
  UnknownDomain = 6,
  UnknownFact = 7,
  DomainNotActive = 8,
  AlreadyRetired = 9,
  CycleNotAllowed = 10,      // containment or supersession cycle
  SelfReference = 11,        // self containment/dependency/shared-fate/independence
  StaleGeneration = 12,      // precondition or binding does not match the model
  ModelMismatch = 13,        // generation matches but content digest differs
  IdempotencyKeyReuse = 14,  // same key, different request
  IdempotencyKeyRequired = 15,
  WriterLockUnavailable = 16,  // another live process owns mutation authority
  Fenced = 17,                 // this writer's epoch is stale; publication refused
  RollbackDetected = 18,       // store generation behind the durable high-water mark
  CorruptState = 19,
  UnsupportedFormatVersion = 20,
  TruncatedState = 21,
  DigestMismatch = 22,
  ReadOnly = 23,
  StorageIo = 24,
  Overflow = 25,
  NotFound = 26,
};

[[nodiscard]] const char* to_string(ErrorCode value) noexcept;
// Stable, machine-readable slug (for example "stale_generation").
[[nodiscard]] const char* error_slug(ErrorCode value) noexcept;

struct Error {
  ErrorCode code{ErrorCode::Ok};
  std::string detail;

  friend bool operator==(const Error&, const Error&) = default;
};

template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}
  Result(Error error) : error_(std::move(error)) {}

  [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return ok(); }

  // Reading the value of a temporary returns by value on purpose: a reference
  // into a Result temporary would dangle as soon as the full expression ends.
  [[nodiscard]] const T& value() const& { return *value_; }
  [[nodiscard]] T& value() & { return *value_; }
  [[nodiscard]] T value() && { return std::move(*value_); }
  [[nodiscard]] const T* operator->() const { return &*value_; }
  [[nodiscard]] T* operator->() { return &*value_; }
  [[nodiscard]] const T& operator*() const& { return *value_; }
  [[nodiscard]] const Error& error() const noexcept { return error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code; }

 private:
  std::optional<T> value_;
  Error error_;
};

class Status {
 public:
  Status() = default;
  Status(Error error) : error_(std::move(error)) {}

  [[nodiscard]] bool ok() const noexcept { return error_.code == ErrorCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] const Error& error() const noexcept { return error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code; }

 private:
  Error error_{};
};

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------
// Every externally influenced quantity is bounded and checked; overflow is
// refused rather than wrapped.
struct Limits {
  std::uint64_t max_domains{200000};
  std::uint64_t max_facts{2000000};
  std::uint64_t max_string_bytes{256};
  std::uint64_t max_natural_key_bytes{192};
  std::uint64_t max_display_name_bytes{128};
  std::uint64_t max_evidence_bytes{256};
  std::uint64_t max_payload_bytes{256ull * 1024ull * 1024ull};
  std::uint64_t max_idempotency_entries{65536};

  friend bool operator==(const Limits&, const Limits&) = default;
};

}  // namespace ffd
