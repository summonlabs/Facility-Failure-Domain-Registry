// Facility Failure Domain Registry - DCCP boundary 49.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ffd/types.hpp"
#include "ffd/version.hpp"

namespace ffd {

namespace detail {
struct SnapshotData;
}  // namespace detail

struct StoreConfig;
class Registry;
class Snapshot;
[[nodiscard]] Result<Snapshot> load_snapshot(const StoreConfig& config);

struct DomainInfo {
  DomainId id;
  DomainClass domain_class{DomainClass::Composite};
  std::string natural_key;
  std::string display_name;
  DomainLifecycle lifecycle{DomainLifecycle::Active};
  DomainId successor;  // valid when lifecycle is Superseded
};

struct MembershipInfo {
  DomainId domain;
  ExternalRef resource;
  std::vector<FactEvidence> evidence;
};

// Why an external reference declared by this model does not resolve to a domain.
enum class ReferenceState : std::uint8_t {
  Resolved = 1,         // exactly one active domain claims the external identity
  NoAlias = 2,          // no domain claims it: the reference stays external
  AmbiguousAlias = 3,   // several domains claim it: preserved as ambiguous
  InactiveTarget = 4,   // internal dependency target is not active
};

struct UnresolvedReference {
  ReferenceState state{ReferenceState::NoAlias};
  DomainId dependent;         // declaring domain
  ExternalRef target;         // external target, when the reference is external
  DomainId internal_target;   // set for InactiveTarget
  std::vector<DomainId> candidates;  // set for AmbiguousAlias
  std::vector<FactEvidence> evidence;
};

enum class PairVerdict : std::uint8_t {
  Unknown = 1,             // no proof either way; unknown is not independence
  ProvenSharedFate = 2,
  ProvenIndependent = 3,
  Conflicting = 4,
};

[[nodiscard]] const char* to_string(PairVerdict value) noexcept;

struct PairVerdictResult {
  PairVerdict verdict{PairVerdict::Unknown};
  // Highest precedence at which a mutual-exposure (shared-fate) proof holds.
  std::uint32_t shared_fate_strength{0};
  // Highest precedence among effective independence claims for the pair.
  std::uint32_t independence_precedence{0};
  std::vector<DomainId> witness_forward;   // subject -> object witness path
  std::vector<DomainId> witness_reverse;   // object -> subject witness path
  std::vector<FactEvidence> shared_fate_evidence;
  std::vector<FactEvidence> independence_evidence;
  std::string explanation;
};

enum class ConflictKind : std::uint8_t {
  Claim = 1,         // equal-precedence claim/retraction contradiction on one slot
  Supersession = 2,  // a domain is claimed superseded by more than one successor
  AmbiguousAlias = 3,  // several domains claim the same external identity
};

[[nodiscard]] const char* to_string(ConflictKind value) noexcept;

struct ConflictInfo {
  ConflictKind kind{ConflictKind::Claim};
  FactKind fact_kind{FactKind::Membership};
  DomainId subject;
  DomainId object;
  ExternalRef external;
  AuthorityId target_authority;
  std::string reason;
  std::vector<FactEvidence> evidence;
};

struct ExposureOptions {
  bool include_self{false};
};

// Immutable, digest-bound, generation-stamped view of the facility failure
// domain model. Snapshots are values: copies share the same immutable data, so
// a snapshot can never observe a later mutation. All queries are const, take no
// locks, and are safe to run concurrently from multiple threads.
class Snapshot {
 public:
  Snapshot(const Snapshot&) = default;
  Snapshot(Snapshot&&) noexcept = default;
  Snapshot& operator=(const Snapshot&) = default;
  Snapshot& operator=(Snapshot&&) noexcept = default;
  ~Snapshot();

  [[nodiscard]] std::uint64_t generation() const noexcept;
  [[nodiscard]] const Digest& digest() const noexcept;
  [[nodiscard]] const Limits& limits() const noexcept;
  [[nodiscard]] ModelBinding binding() const noexcept;
  [[nodiscard]] std::size_t domain_count() const noexcept;
  [[nodiscard]] std::size_t fact_count() const noexcept;

  // Refuses with StaleGeneration when the generation differs, and with
  // ModelMismatch when the generation matches but the content digest differs.
  [[nodiscard]] Status verify_binding(const ModelBinding& binding) const;

  [[nodiscard]] Result<DomainInfo> domain(DomainId id) const;
  [[nodiscard]] Result<std::vector<DomainInfo>> domains(bool include_inactive = false) const;

  // Explicit memberships declared for a domain.
  [[nodiscard]] Result<std::vector<MembershipInfo>> memberships(DomainId domain) const;
  // All domains that explicitly declare membership of the resource.
  [[nodiscard]] Result<std::vector<DomainId>> containing_domains(const ExternalRef& resource,
                                                                 bool include_inactive = false) const;
  // Containment ancestors of the domains that declare membership of the
  // resource. Nesting is reported separately from membership on purpose.
  [[nodiscard]] Result<std::vector<DomainId>> enclosing_domains(const ExternalRef& resource,
                                                                bool include_inactive = false) const;
  // Active domains that claim the external identity through an alias.
  [[nodiscard]] Result<std::vector<DomainId>> domains_for_reference(const ExternalRef& resource) const;

  [[nodiscard]] Result<std::vector<DomainId>> upstream_exposure(DomainId target,
                                                                ExposureOptions options = {}) const;
  [[nodiscard]] Result<std::vector<DomainId>> downstream_exposure(DomainId target,
                                                                  ExposureOptions options = {}) const;
  // Domains whose failure exposes every listed target (single points of failure
  // for the set).
  [[nodiscard]] Result<std::vector<DomainId>> common_exposers(const std::vector<DomainId>& targets,
                                                              ExposureOptions options = {}) const;
  // Everything exposed by the failure of any listed target.
  [[nodiscard]] Result<std::vector<DomainId>> blast_radius(const std::vector<DomainId>& targets,
                                                           ExposureOptions options = {}) const;
  // Resources co-located with every listed resource in at least one common
  // failure domain.
  [[nodiscard]] Result<std::vector<ExternalRef>> jointly_exposed_resources(
      const std::vector<ExternalRef>& resources) const;

  [[nodiscard]] Result<std::vector<DomainId>> shared_fate_group(DomainId target) const;
  [[nodiscard]] Result<std::vector<DomainId>> successors(DomainId target) const;
  [[nodiscard]] Result<PairVerdictResult> pair_verdict(DomainId a, DomainId b) const;
  [[nodiscard]] Result<std::vector<FactEvidence>> evidence_for(const ClaimRef& claim) const;
  [[nodiscard]] Result<std::vector<ConflictInfo>> conflicts() const;
  [[nodiscard]] Result<std::vector<UnresolvedReference>> unresolved_references() const;

  // Deterministic, human-readable rendering of the resolved model. Stable for a
  // given content digest; intended for diagnostics and golden comparisons.
  [[nodiscard]] std::string canonical_text() const;

 private:
  friend class Registry;
  friend Result<Snapshot> load_snapshot(const StoreConfig& config);
  explicit Snapshot(std::shared_ptr<const detail::SnapshotData> data);

  std::shared_ptr<const detail::SnapshotData> data_;
};

}  // namespace ffd
