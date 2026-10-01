// Facility Failure Domain Registry - DCCP boundary 49.
//
// Internal representation of the declared model and its resolved form. The
// resolved form is what queries and digests observe: every claim is classified
// as effective, superseded-by-revision, outranked or conflicting.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ffd/snapshot.hpp"
#include "ffd/types.hpp"

namespace ffd::detail {

struct DomainRecord {
  DomainId id;
  DomainClass domain_class{DomainClass::Composite};
  std::string natural_key;
  std::string display_name;
};

// One immutable declared claim. Facts are append-only: nothing is edited or
// removed, so provenance survives precedence and retraction.
struct FactRecord {
  std::uint64_t id{0};  // session-local handle, deliberately not content
  FactKind kind{FactKind::Membership};
  FactKind target_kind{FactKind::Membership};  // Retraction only: kind retracted
  DomainId subject;
  DomainId object;
  ExternalRef external;
  // True when the claim (or, for a Retraction, the retracted claim slot) carries
  // an external reference instead of a domain object.
  bool external_target{false};
  AuthorityId target_authority;  // Retraction only: authority whose claim is disputed
  Provenance provenance;
};

struct JournalEntry {
  IdempotencyKey key;
  Digest request_fingerprint;
  std::uint64_t generation_after{0};
  Digest digest_after;
  DomainId result_domain;
  ClaimRef result_claim;
  bool result_claim_valid{false};
  std::uint64_t sequence{0};
};

// Duplicate-claim key: the same authority at the same revision declaring the
// same claim is one claim, so a repeat is refused rather than accumulated.
struct FactKey {
  FactKind kind{FactKind::Membership};
  FactKind target_kind{FactKind::Membership};
  DomainId subject;
  DomainId object;
  ExternalRef external;
  bool external_target{false};
  AuthorityId target_authority;
  AuthorityId authority;
  std::uint64_t authority_revision{0};

  friend bool operator<(const FactKey& a, const FactKey& b) noexcept {
    if (a.kind != b.kind) return a.kind < b.kind;
    if (a.target_kind != b.target_kind) return a.target_kind < b.target_kind;
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.object != b.object) return a.object < b.object;
    if (a.external != b.external) return a.external < b.external;
    if (a.external_target != b.external_target) return a.external_target < b.external_target;
    if (a.target_authority != b.target_authority) return a.target_authority < b.target_authority;
    if (a.authority != b.authority) return a.authority < b.authority;
    return a.authority_revision < b.authority_revision;
  }
};

[[nodiscard]] FactKey fact_key_of(const FactRecord& fact) noexcept;

struct ModelState {
  std::map<DomainId, DomainRecord> domains;
  std::vector<FactRecord> facts;
  std::map<AuthorityId, std::uint32_t> precedence;
  std::uint64_t identity_high_water{0};
  std::uint64_t fact_high_water{0};
  std::map<IdempotencyKey, JournalEntry> journal;
  std::uint64_t journal_sequence{0};
  std::uint64_t generation{0};

  [[nodiscard]] std::uint32_t precedence_of(const AuthorityId& authority) const noexcept;
  [[nodiscard]] bool has_natural_key(const DomainKey& key) const noexcept;
};

inline constexpr std::uint32_t kDefaultAuthorityPrecedence = 1;

// Canonical identity of a claim slot. The same (kind, subject, object/external)
// declared twice is the same slot, regardless of declaration order.
struct SlotKey {
  FactKind kind{FactKind::Membership};
  DomainId subject;
  DomainId object;
  ExternalRef external;

  friend bool operator==(const SlotKey&, const SlotKey&) = default;
  friend auto operator<=>(const SlotKey&, const SlotKey&) = default;
};

[[nodiscard]] SlotKey canonical_slot(FactKind kind, DomainId subject, DomainId object,
                                     const ExternalRef& external);
[[nodiscard]] ClaimRef claim_ref_of(const SlotKey& key);

struct EffectiveEdge {
  DomainId from;
  DomainId to;
  std::uint32_t precedence{0};
  SlotKey source;
};

struct SlotResolution {
  bool asserted{false};
  bool retracted{false};
  bool conflicted{false};
  std::uint32_t precedence{0};
  std::vector<FactEvidence> evidence;
};

struct ResolvedModel {
  std::uint64_t generation{0};
  Digest digest;
  Limits limits;

  std::vector<DomainRecord> domains;               // ordered by DomainId
  std::map<DomainId, std::size_t> domain_index;
  std::map<DomainId, DomainLifecycle> lifecycle;
  std::map<DomainId, DomainId> successor;
  std::vector<FactRecord> facts;                   // canonical order
  std::vector<FactEvidence> evidence;              // canonical order
  std::map<SlotKey, SlotResolution> slots;

  std::vector<EffectiveEdge> edges;                // effective, active endpoints
  std::vector<std::vector<std::uint32_t>> adjacency;  // out-edges by domain index
  std::vector<std::uint32_t> component;            // SCC id per domain index (threshold 1)

  std::map<ExternalRef, std::vector<DomainId>> members;   // effective membership
  std::map<ExternalRef, std::vector<DomainId>> aliases;   // effective alias claims

  std::vector<ConflictInfo> conflicts;
  std::vector<UnresolvedReference> unresolved;
  // Containment relation by domain index (enclosing -> enclosed), used by cycle
  // detection and by the enclosure query.
  std::vector<std::vector<std::uint32_t>> containment_adjacency;

  [[nodiscard]] bool is_active(DomainId id) const noexcept;
  [[nodiscard]] const DomainRecord* find_domain(DomainId id) const noexcept;
  [[nodiscard]] std::size_t index_of(DomainId id) const noexcept;
};

// Immutable snapshot payload shared by value copies of ffd::Snapshot.
struct SnapshotData {
  ResolvedModel model;
};

// Resolves a declared model. Refuses structurally illegal state (containment or
// supersession cycles, dangling identities, duplicate natural keys, unknown
// enumerators). loading==true maps structural refusals to CorruptState, because
// the caller is validating decoded durable state rather than accepting input.
[[nodiscard]] Result<ResolvedModel> resolve_model(const ModelState& state, const Limits& limits,
                                                  bool loading);

[[nodiscard]] bool canonical_fact_less(const FactRecord& a, const FactRecord& b) noexcept;
[[nodiscard]] std::vector<const FactRecord*> canonical_fact_pointers(const ModelState& state);

}  // namespace ffd::detail
