// Facility Failure Domain Registry - DCCP boundary 49.
//
// Writer side. One Registry owns mutation authority for one store. Every public
// entry point takes exactly one internal mutex, releases it before returning,
// and never calls another locked entry point: all internal helpers are methods
// of the Impl and take explicit arguments. There are no callbacks, no worker
// threads and no nested lock acquisition anywhere on these call paths.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "canonical.hpp"
#include "checked.hpp"
#include "ffd/registry.hpp"
#include "model.hpp"
#include "sha256.hpp"
#include "storage.hpp"
#include "validate.hpp"

namespace ffd {
namespace {

using detail::DomainRecord;
using detail::FactRecord;
using detail::JournalEntry;
using detail::ModelState;
using detail::ResolvedModel;

[[nodiscard]] Error make_error(ErrorCode code, std::string detail) {
  return Error{code, std::move(detail)};
}

// Canonical description of a requested mutation. It deliberately excludes the
// precondition: retrying the same operation with a different (or absent)
// expected generation is still the same operation.
class RequestFingerprint {
 public:
  void op(std::string_view name) { op_.assign(name); }
  void text(std::string_view value) { writer_.str(value); }
  void id(DomainId value) { writer_.u64(value.value); }
  void kind(FactKind value) { writer_.u16(static_cast<std::uint16_t>(value)); }
  void domain_class(DomainClass value) { writer_.u16(static_cast<std::uint16_t>(value)); }
  void flag(bool value) { writer_.u8(value ? 1u : 0u); }
  void external(const ExternalRef& ref) {
    writer_.str(ref.authority.value);
    writer_.str(ref.resource.value);
  }
  [[nodiscard]] Digest finish() const {
    detail::Sha256 hasher;
    hasher.update(op_);
    hasher.update(writer_.bytes().data(), writer_.size());
    return hasher.finish();
  }

 private:
  std::string op_;
  detail::ByteWriter writer_;
};

// Undo record for one in-place mutation attempt. A mutation is applied directly
// to the authoritative state and rolled back unless it resolves into a valid
// model and is durably published. Nothing is copied on the common path.
struct Undo {
  bool domain_removed{false};
  DomainId removed_domain;
  bool fact_removed{false};
  bool precedence_changed{false};
  AuthorityId precedence_authority;
  bool precedence_existed{false};
  std::uint32_t precedence_value{0};
  std::uint64_t identity_high_water{0};
  std::uint64_t fact_high_water{0};
  std::uint64_t generation{0};
  bool journal_removed{false};
  IdempotencyKey journal_key;
  bool journal_evicted{false};
  IdempotencyKey evicted_key;
  JournalEntry evicted_entry;
  detail::FactKey appended_key;

  void revert(ModelState& state) const {
    if (domain_removed) {
      state.domains.erase(removed_domain);
    }
    if (fact_removed && !state.facts.empty()) {
      state.facts.pop_back();
    }
    if (precedence_changed) {
      if (precedence_existed) {
        state.precedence[precedence_authority] = precedence_value;
      } else {
        state.precedence.erase(precedence_authority);
      }
    }
    if (journal_removed) {
      state.journal.erase(journal_key);
    }
    if (journal_evicted) {
      state.journal.emplace(evicted_key, evicted_entry);
    }
    state.identity_high_water = identity_high_water;
    state.fact_high_water = fact_high_water;
    state.generation = generation;
  }
};

[[nodiscard]] FactRecord make_fact(FactKind kind, DomainId subject, DomainId object,
                                   const ExternalRef& external, bool external_target,
                                   const Provenance& provenance) {
  FactRecord fact;
  fact.kind = kind;
  fact.target_kind = kind;
  fact.subject = subject;
  fact.object = object;
  fact.external = external;
  fact.external_target = external_target;
  fact.provenance = provenance;
  return fact;
}

}  // namespace

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------
struct Registry::Impl {
  StoreConfig config;
  StoreInfo info;
  std::unique_ptr<detail::StoreFile> store;
  ModelState state;
  std::shared_ptr<const detail::SnapshotData> current;
  std::set<detail::FactKey> fact_keys;
  std::set<DomainKey> domain_keys;
  std::uint64_t writer_epoch{0};
  bool uncommitted{false};
  mutable std::mutex mutex;

  [[nodiscard]] Status validate_context(const MutationContext& context) const {
    Status status = detail::validate_provenance(context.provenance, config.limits);
    if (!status.ok()) {
      return status;
    }
    if (!context.key.has_value()) {
      if (config.key_policy == MutationKeyPolicy::Required) {
        return Status(make_error(ErrorCode::IdempotencyKeyRequired,
                                 "this store requires an idempotency key for every mutation"));
      }
      return Status{};
    }
    return detail::validate_idempotency_key(*context.key, config.limits);
  }

  [[nodiscard]] Status require_active(DomainId id) const {
    if (!id.valid()) {
      return Status(make_error(ErrorCode::InvalidArgument, "domain id must be valid"));
    }
    if (state.domains.find(id) == state.domains.end()) {
      return Status(make_error(ErrorCode::UnknownDomain,
                               "domain " + std::to_string(id.value) + " is unknown"));
    }
    const auto lifecycle = current->model.lifecycle.find(id);
    if (lifecycle != current->model.lifecycle.end() &&
        lifecycle->second != DomainLifecycle::Active) {
      return Status(make_error(ErrorCode::DomainNotActive,
                               "domain " + std::to_string(id.value) + " is " +
                                   to_string(lifecycle->second)));
    }
    return Status{};
  }

  [[nodiscard]] Status require_exists(DomainId id) const {
    if (!id.valid()) {
      return Status(make_error(ErrorCode::InvalidArgument, "domain id must be valid"));
    }
    if (state.domains.find(id) == state.domains.end()) {
      return Status(make_error(ErrorCode::UnknownDomain,
                               "domain " + std::to_string(id.value) + " is unknown"));
    }
    return Status{};
  }

  [[nodiscard]] Result<DomainId> allocate_identity(
      ModelState& target, const std::optional<DomainId>& requested) const {
    if (requested.has_value()) {
      if (!requested->valid()) {
        return make_error(ErrorCode::InvalidArgument, "requested identity must be positive");
      }
      if (target.domains.find(*requested) != target.domains.end()) {
        return make_error(ErrorCode::DuplicateIdentity,
                          "identity " + std::to_string(requested->value) + " is already issued");
      }
      if (requested->value <= target.identity_high_water) {
        return make_error(ErrorCode::DuplicateIdentity,
                          "identity " + std::to_string(requested->value) +
                              " was already issued and identities are never reused");
      }
      target.identity_high_water = requested->value;
      return *requested;
    }
    const std::optional<std::uint64_t> next =
        detail::checked_add(target.identity_high_water, 1ull);
    if (!next.has_value()) {
      return make_error(ErrorCode::Overflow, "domain identity space is exhausted");
    }
    target.identity_high_water = next.value();
    return DomainId{next.value()};
  }

  [[nodiscard]] Status append_fact(ModelState& target, Undo& undo, const FactRecord& fact) const {
    if (target.facts.size() >= config.limits.max_facts) {
      return Status(make_error(ErrorCode::LimitExceeded, "fact limit reached"));
    }
    if (fact_keys.find(detail::fact_key_of(fact)) != fact_keys.end()) {
      return Status(make_error(ErrorCode::DuplicateClaim,
                               "the same authority already declared this claim at this revision"));
    }
    const std::optional<std::uint64_t> next = detail::checked_add(target.fact_high_water, 1ull);
    if (!next.has_value()) {
      return Status(make_error(ErrorCode::Overflow, "fact identity space is exhausted"));
    }
    FactRecord stored = fact;
    target.fact_high_water = next.value();
    stored.id = next.value();
    undo.appended_key = detail::fact_key_of(stored);
    target.facts.push_back(std::move(stored));
    undo.fact_removed = true;
    return Status{};
  }

  template <class Apply>
  Result<MutationOutcome> commit(const MutationContext& context, const Digest& fingerprint,
                                 Apply&& apply) {
    const Status context_status = validate_context(context);
    if (!context_status.ok()) {
      return context_status.error();
    }

    // Idempotent replay is resolved before the stale-precondition check: a lost
    // response must never cause a second consequential mutation, even when the
    // caller's precondition is now behind.
    if (context.key.has_value()) {
      const auto existing = state.journal.find(*context.key);
      if (existing != state.journal.end()) {
        if (existing->second.request_fingerprint == fingerprint) {
          MutationOutcome outcome;
          outcome.generation = existing->second.generation_after;
          outcome.digest = existing->second.digest_after;
          outcome.replayed = true;
          outcome.domain = existing->second.result_domain;
          outcome.claim = existing->second.result_claim;
          outcome.claim_valid = existing->second.result_claim_valid;
          return outcome;
        }
        return make_error(ErrorCode::IdempotencyKeyReuse,
                          "idempotency key was already used for a different request");
      }
    }

    if (context.expected_generation != 0 && context.expected_generation != state.generation) {
      return make_error(ErrorCode::StaleGeneration,
                        "expected generation " + std::to_string(context.expected_generation) +
                            " but the model is at generation " +
                            std::to_string(state.generation));
    }

    Undo undo;
    undo.identity_high_water = state.identity_high_water;
    undo.fact_high_water = state.fact_high_water;
    undo.generation = state.generation;

    Result<MutationOutcome> applied = apply(state, undo);
    if (!applied.ok()) {
      undo.revert(state);
      return applied.error();
    }
    MutationOutcome outcome = applied.value();

    const std::optional<std::uint64_t> next_generation =
        detail::checked_add(state.generation, 1ull);
    if (!next_generation.has_value()) {
      undo.revert(state);
      return make_error(ErrorCode::Overflow, "generation counter is exhausted");
    }
    state.generation = next_generation.value();

    Result<ResolvedModel> resolved = detail::resolve_model(state, config.limits, false);
    if (!resolved.ok()) {
      undo.revert(state);
      return resolved.error();
    }
    const Digest digest = resolved.value().digest;
    outcome.generation = state.generation;
    outcome.digest = digest;

    if (context.key.has_value()) {
      if (state.journal.size() >= config.limits.max_idempotency_entries) {
        auto oldest = state.journal.begin();
        for (auto it = state.journal.begin(); it != state.journal.end(); ++it) {
          if (it->second.sequence < oldest->second.sequence) {
            oldest = it;
          }
        }
        undo.journal_evicted = true;
        undo.evicted_key = oldest->first;
        undo.evicted_entry = oldest->second;
        state.journal.erase(oldest);
      }
      const std::optional<std::uint64_t> next_sequence =
          detail::checked_add(state.journal_sequence, 1ull);
      if (!next_sequence.has_value()) {
        undo.revert(state);
        return make_error(ErrorCode::Overflow, "idempotency journal sequence is exhausted");
      }
      state.journal_sequence = next_sequence.value();
      JournalEntry entry;
      entry.key = *context.key;
      entry.request_fingerprint = fingerprint;
      entry.generation_after = state.generation;
      entry.digest_after = digest;
      entry.result_domain = outcome.domain;
      entry.result_claim = outcome.claim;
      entry.result_claim_valid = outcome.claim_valid;
      entry.sequence = state.journal_sequence;
      undo.journal_removed = true;
      undo.journal_key = *context.key;
      state.journal.emplace(*context.key, std::move(entry));
    }

    if (config.durability == Durability::DurablePerMutation) {
      const Status published = store->publish(state, state.generation, digest);
      if (!published.ok()) {
        undo.revert(state);
        return published.error();
      }
      uncommitted = false;
    } else {
      uncommitted = true;
    }

    // Indexes that back duplicate detection only advance once the mutation is
    // durable, so a rolled-back attempt never poisons them.
    if (undo.fact_removed) {
      fact_keys.insert(undo.appended_key);
    }
    current = std::make_shared<detail::SnapshotData>(
        detail::SnapshotData{std::move(resolved.value())});
    return outcome;
  }

  [[nodiscard]] Result<MutationOutcome> create_domain(const CreateDomainRequest& request) {
    const Limits& limits = config.limits;
    Status status = detail::validate_natural_key(request.natural_key, limits);
    if (!status.ok()) {
      return status.error();
    }
    status = detail::validate_display_name(request.display_name, limits);
    if (!status.ok()) {
      return status.error();
    }
    if (!is_known_domain_class(static_cast<std::uint16_t>(request.domain_class))) {
      return make_error(ErrorCode::InvalidArgument, "domain class is not a known class");
    }
    RequestFingerprint fingerprint;
    fingerprint.op("create_domain");
    fingerprint.domain_class(request.domain_class);
    fingerprint.text(request.natural_key);
    fingerprint.text(request.display_name);
    fingerprint.flag(request.requested_id.has_value());
    if (request.requested_id.has_value()) {
      fingerprint.id(*request.requested_id);
    }

    const DomainKey key{request.domain_class, request.natural_key};
    Result<MutationOutcome> outcome =
        commit(request.context, fingerprint.finish(),
               [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                 if (domain_keys.find(key) != domain_keys.end()) {
                   return make_error(ErrorCode::DuplicateNaturalKey,
                                     "a domain with this class and natural key already exists");
                 }
                 if (target.domains.size() >= limits.max_domains) {
                   return make_error(ErrorCode::LimitExceeded, "domain limit reached");
                 }
                 Result<DomainId> identity = allocate_identity(target, request.requested_id);
                 if (!identity.ok()) {
                   return identity.error();
                 }
                 DomainRecord record;
                 record.id = identity.value();
                 record.domain_class = request.domain_class;
                 record.natural_key = request.natural_key;
                 record.display_name = request.display_name;
                 target.domains.emplace(record.id, record);
                 undo.domain_removed = true;
                 undo.removed_domain = record.id;
                 MutationOutcome result;
                 result.domain = record.id;
                 return result;
               });
    if (outcome.ok()) {
      domain_keys.insert(key);
    }
    return outcome;
  }

  [[nodiscard]] Result<MutationOutcome> retire_domain(const RetireDomainRequest& request) {
    const Status active = require_active(request.domain);
    if (!active.ok()) {
      if (active.code() == ErrorCode::DomainNotActive) {
        return make_error(ErrorCode::AlreadyRetired, active.error().detail);
      }
      return active.error();
    }
    const Status evidence_status =
        detail::validate_evidence(request.reason, config.limits);
    if (!evidence_status.ok()) {
      return evidence_status.error();
    }
    RequestFingerprint fingerprint;
    fingerprint.op("retire_domain");
    fingerprint.id(request.domain);

    Provenance provenance = request.context.provenance;
    if (!request.reason.empty()) {
      provenance.evidence = request.reason;
    }
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact;
                    fact.kind = FactKind::Retirement;
                    fact.target_kind = FactKind::Retirement;
                    fact.subject = request.domain;
                    fact.provenance = provenance;
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    ClaimRef claim;
                    claim.kind = FactKind::Retirement;
                    claim.target_kind = FactKind::Retirement;
                    claim.subject = request.domain;
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> supersede_domain(const SupersedeDomainRequest& request) {
    // A replacement may be declared for an active, retired or already superseded
    // predecessor. A second, competing successor claim is accepted and preserved
    // as a conflict rather than refused, so an equal-authority disagreement stays
    // visible; only an unambiguous successor takes effect.
    const Status predecessor = require_exists(request.predecessor);
    if (!predecessor.ok()) {
      return predecessor.error();
    }
    const Limits& limits = config.limits;
    Status status = detail::validate_natural_key(request.natural_key, limits);
    if (!status.ok()) {
      return status.error();
    }
    status = detail::validate_display_name(request.display_name, limits);
    if (!status.ok()) {
      return status.error();
    }
    if (!is_known_domain_class(static_cast<std::uint16_t>(request.domain_class))) {
      return make_error(ErrorCode::InvalidArgument, "domain class is not a known class");
    }
    RequestFingerprint fingerprint;
    fingerprint.op("supersede_domain");
    fingerprint.id(request.predecessor);
    fingerprint.domain_class(request.domain_class);
    fingerprint.text(request.natural_key);
    fingerprint.text(request.display_name);

    const DomainKey key{request.domain_class, request.natural_key};
    Result<MutationOutcome> outcome =
        commit(request.context, fingerprint.finish(),
               [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                 if (domain_keys.find(key) != domain_keys.end()) {
                   return make_error(ErrorCode::DuplicateNaturalKey,
                                     "a domain with this class and natural key already exists");
                 }
                 if (target.domains.size() >= limits.max_domains) {
                   return make_error(ErrorCode::LimitExceeded, "domain limit reached");
                 }
                 Result<DomainId> identity = allocate_identity(target, std::nullopt);
                 if (!identity.ok()) {
                   return identity.error();
                 }
                 DomainRecord record;
                 record.id = identity.value();
                 record.domain_class = request.domain_class;
                 record.natural_key = request.natural_key;
                 record.display_name = request.display_name;
                 target.domains.emplace(record.id, record);
                 undo.domain_removed = true;
                 undo.removed_domain = record.id;

                 FactRecord fact;
                 fact.kind = FactKind::Supersession;
                 fact.target_kind = FactKind::Supersession;
                 fact.subject = request.predecessor;
                 fact.object = record.id;
                 fact.provenance = request.context.provenance;
                 const Status appended = append_fact(target, undo, fact);
                 if (!appended.ok()) {
                   return appended.error();
                 }
                 MutationOutcome result;
                 result.domain = record.id;
                 ClaimRef claim;
                 claim.kind = FactKind::Supersession;
                 claim.target_kind = FactKind::Supersession;
                 claim.subject = request.predecessor;
                 claim.object = record.id;
                 result.claim = claim;
                 result.claim_valid = true;
                 return result;
               });
    if (outcome.ok()) {
      domain_keys.insert(key);
    }
    return outcome;
  }

  [[nodiscard]] Result<MutationOutcome> add_membership(const AddMembershipRequest& request) {
    const Status external_status = detail::validate_external_ref(request.resource, config.limits);
    if (!external_status.ok()) {
      return external_status.error();
    }
    const Status active = require_active(request.domain);
    if (!active.ok()) {
      return active.error();
    }
    RequestFingerprint fingerprint;
    fingerprint.op("add_membership");
    fingerprint.id(request.domain);
    fingerprint.external(request.resource);
    const ExternalRef resource = request.resource;
    const DomainId domain = request.domain;
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact = make_fact(FactKind::Membership, domain, DomainId{}, resource,
                                                true, request.context.provenance);
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = domain;
                    ClaimRef claim;
                    claim.kind = FactKind::Membership;
                    claim.target_kind = FactKind::Membership;
                    claim.subject = domain;
                    claim.external = resource;
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> declare_alias(const DeclareAliasRequest& request) {
    const Status external_status = detail::validate_external_ref(request.resource, config.limits);
    if (!external_status.ok()) {
      return external_status.error();
    }
    const Status active = require_active(request.domain);
    if (!active.ok()) {
      return active.error();
    }
    RequestFingerprint fingerprint;
    fingerprint.op("declare_alias");
    fingerprint.id(request.domain);
    fingerprint.external(request.resource);
    const ExternalRef resource = request.resource;
    const DomainId domain = request.domain;
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact = make_fact(FactKind::ExternalAlias, domain, DomainId{},
                                                resource, true, request.context.provenance);
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = domain;
                    ClaimRef claim;
                    claim.kind = FactKind::ExternalAlias;
                    claim.target_kind = FactKind::ExternalAlias;
                    claim.subject = domain;
                    claim.external = resource;
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> declare_containment(
      const DeclareContainmentRequest& request) {
    if (request.parent == request.child) {
      return make_error(ErrorCode::SelfReference, "a domain cannot contain itself");
    }
    const Status parent_status = require_active(request.parent);
    if (!parent_status.ok()) {
      return parent_status.error();
    }
    const Status child_status = require_active(request.child);
    if (!child_status.ok()) {
      return child_status.error();
    }
    RequestFingerprint fingerprint;
    fingerprint.op("declare_containment");
    fingerprint.id(request.parent);
    fingerprint.id(request.child);
    const DomainId parent = request.parent;
    const DomainId child = request.child;
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact = make_fact(FactKind::Containment, parent, child, ExternalRef{},
                                                false, request.context.provenance);
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = parent;
                    ClaimRef claim;
                    claim.kind = FactKind::Containment;
                    claim.target_kind = FactKind::Containment;
                    claim.subject = parent;
                    claim.object = child;
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> declare_dependency(
      const DeclareDependencyRequest& request) {
    const bool has_internal = request.target.has_value();
    const bool has_external = request.external_target.has_value();
    if (has_internal == has_external) {
      return make_error(ErrorCode::InvalidArgument,
                        "exactly one of target and external_target must be set");
    }
    // Structural impossibilities are refused before any state is consulted, so
    // the same malformed request is diagnosed identically in every lifecycle.
    if (has_internal && *request.target == request.dependent) {
      return make_error(ErrorCode::SelfReference, "a domain cannot depend on itself");
    }
    const Status dependent_status = require_active(request.dependent);
    if (!dependent_status.ok()) {
      return dependent_status.error();
    }
    if (has_internal) {
      const Status target_status = require_active(*request.target);
      if (!target_status.ok()) {
        return target_status.error();
      }
    } else {
      const Status external_status =
          detail::validate_external_ref(*request.external_target, config.limits);
      if (!external_status.ok()) {
        return external_status.error();
      }
    }

    RequestFingerprint fingerprint;
    fingerprint.op("declare_dependency");
    fingerprint.id(request.dependent);
    fingerprint.flag(has_internal);
    if (has_internal) {
      fingerprint.id(*request.target);
    } else {
      fingerprint.external(*request.external_target);
    }
    const DomainId dependent = request.dependent;
    const std::optional<DomainId> target = request.target;
    const std::optional<ExternalRef> external_target = request.external_target;
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target_state, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact;
                    fact.kind = FactKind::Dependency;
                    fact.target_kind = FactKind::Dependency;
                    fact.subject = dependent;
                    if (target.has_value()) {
                      fact.object = *target;
                    } else {
                      fact.external = *external_target;
                      fact.external_target = true;
                    }
                    fact.provenance = request.context.provenance;
                    const Status appended = append_fact(target_state, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = dependent;
                    ClaimRef claim;
                    claim.kind = FactKind::Dependency;
                    claim.target_kind = FactKind::Dependency;
                    claim.subject = dependent;
                    claim.object = target.value_or(DomainId{});
                    claim.external = external_target.value_or(ExternalRef{});
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> declare_shared_fate(
      const DeclareSharedFateRequest& request) {
    return declare_pair(request.context, request.a, request.b, FactKind::SharedFate, "shared_fate");
  }

  [[nodiscard]] Result<MutationOutcome> declare_independence(
      const DeclareIndependenceRequest& request) {
    // Independence is never inferred and never inherited through containment.
    // A claim that contradicts a proven shared fate is preserved as a conflict
    // rather than rejected, so an equal-precedence disagreement stays visible.
    return declare_pair(request.context, request.a, request.b, FactKind::Independence,
                        "independence");
  }

  [[nodiscard]] Result<MutationOutcome> declare_pair(const MutationContext& context, DomainId a,
                                                     DomainId b, FactKind kind,
                                                     std::string_view op) {
    if (a == b) {
      return make_error(ErrorCode::SelfReference,
                        "a domain cannot be related to itself by this relationship");
    }
    const Status a_status = require_active(a);
    if (!a_status.ok()) {
      return a_status.error();
    }
    const Status b_status = require_active(b);
    if (!b_status.ok()) {
      return b_status.error();
    }
    RequestFingerprint fingerprint;
    fingerprint.op(op);
    fingerprint.id(a);
    fingerprint.id(b);
    return commit(context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    const detail::SlotKey slot = detail::canonical_slot(kind, a, b, ExternalRef{});
                    FactRecord fact = make_fact(kind, slot.subject, slot.object, ExternalRef{},
                                                false, context.provenance);
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = slot.subject;
                    ClaimRef claim;
                    claim.kind = kind;
                    claim.target_kind = kind;
                    claim.subject = slot.subject;
                    claim.object = slot.object;
                    result.claim = claim;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> revoke_claim(const RevokeClaimRequest& request) {
    const ClaimRef& claim = request.claim;
    const FactKind slot_kind =
        claim.kind == FactKind::Retraction ? claim.target_kind : claim.kind;
    if (slot_kind == FactKind::Retraction) {
      return make_error(ErrorCode::InvalidArgument, "a retraction cannot target a retraction");
    }
    if (!is_known_fact_kind(static_cast<std::uint16_t>(slot_kind))) {
      return make_error(ErrorCode::InvalidArgument, "claim kind is not known");
    }
    if (claim.target_authority.empty()) {
      return make_error(ErrorCode::InvalidArgument,
                        "a retraction must name the authority whose claim it disputes");
    }
    const Status authority_status =
        detail::validate_authority(claim.target_authority, config.limits);
    if (!authority_status.ok()) {
      return authority_status.error();
    }
    const Status subject_status = require_active(claim.subject);
    if (!subject_status.ok()) {
      return subject_status.error();
    }
    const detail::SlotKey slot = detail::canonical_slot(slot_kind, claim.subject, claim.object,
                                                        claim.external);
    if (slot.object.valid()) {
      const Status object_status = require_active(slot.object);
      if (!object_status.ok()) {
        return object_status.error();
      }
    }
    if (is_external_fact_kind(slot_kind)) {
      const Status external_status = detail::validate_external_ref(slot.external, config.limits);
      if (!external_status.ok()) {
        return external_status.error();
      }
    }

    // The disputed claim must exist: retractions of nothing are refused rather
    // than recorded as evidence about an absent claim.
    bool found = false;
    for (const FactRecord& fact : state.facts) {
      if (fact.kind == FactKind::Retraction) {
        continue;
      }
      if (fact.kind != slot_kind || !(fact.subject == slot.subject) ||
          !(fact.object == slot.object) || !(fact.external == slot.external) ||
          !(fact.provenance.authority == claim.target_authority)) {
        continue;
      }
      found = true;
      break;
    }
    if (!found) {
      return make_error(ErrorCode::UnknownFact,
                        "no claim from that authority exists on the named slot");
    }

    RequestFingerprint fingerprint;
    fingerprint.op("revoke_claim");
    fingerprint.kind(FactKind::Retraction);
    fingerprint.kind(slot_kind);
    fingerprint.id(slot.subject);
    fingerprint.id(slot.object);
    fingerprint.external(slot.external);
    fingerprint.text(claim.target_authority.value);
    const detail::SlotKey target_slot = slot;
    const AuthorityId target_authority = claim.target_authority;
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    FactRecord fact;
                    fact.kind = FactKind::Retraction;
                    fact.target_kind = slot_kind;
                    fact.subject = target_slot.subject;
                    fact.object = target_slot.object;
                    fact.external = target_slot.external;
                    fact.external_target = is_external_fact_kind(slot_kind) ||
                                           (slot_kind == FactKind::Dependency &&
                                            !target_slot.external.empty());
                    fact.target_authority = target_authority;
                    fact.provenance = request.context.provenance;
                    const Status appended = append_fact(target, undo, fact);
                    if (!appended.ok()) {
                      return appended.error();
                    }
                    MutationOutcome result;
                    result.domain = target_slot.subject;
                    ClaimRef produced;
                    produced.kind = FactKind::Retraction;
                    produced.target_kind = slot_kind;
                    produced.subject = target_slot.subject;
                    produced.object = target_slot.object;
                    produced.external = target_slot.external;
                    produced.target_authority = target_authority;
                    result.claim = produced;
                    result.claim_valid = true;
                    return result;
                  });
  }

  [[nodiscard]] Result<MutationOutcome> set_authority_precedence(
      const SetAuthorityPrecedenceRequest& request) {
    const Status authority_status = detail::validate_authority(request.authority, config.limits);
    if (!authority_status.ok()) {
      return authority_status.error();
    }
    if (request.precedence == 0 || request.precedence > 1000000u) {
      return make_error(ErrorCode::InvalidArgument,
                        "authority precedence must be between 1 and 1000000");
    }
    RequestFingerprint fingerprint;
    fingerprint.op("set_authority_precedence");
    fingerprint.text(request.authority.value);
    fingerprint.id(DomainId{request.precedence});
    return commit(request.context, fingerprint.finish(),
                  [&](ModelState& target, Undo& undo) -> Result<MutationOutcome> {
                    const auto existing = target.precedence.find(request.authority);
                    if (existing != target.precedence.end()) {
                      undo.precedence_changed = true;
                      undo.precedence_authority = request.authority;
                      undo.precedence_existed = true;
                      undo.precedence_value = existing->second;
                    } else {
                      undo.precedence_changed = true;
                      undo.precedence_authority = request.authority;
                      undo.precedence_existed = false;
                    }
                    target.precedence[request.authority] = request.precedence;
                    MutationOutcome result;
                    return result;
                  });
  }

  [[nodiscard]] Status publish() {
    if (!uncommitted) {
      return Status{};
    }
    const Status published = store->publish(state, state.generation, current->model.digest);
    if (!published.ok()) {
      return published;
    }
    uncommitted = false;
    return Status{};
  }
};

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------
Registry::Registry(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Registry::~Registry() = default;

Result<std::unique_ptr<Registry>> Registry::open(const StoreConfig& config) {
  const Status limits_status = detail::validate_limits(config.limits);
  if (!limits_status.ok()) {
    return limits_status.error();
  }
  if (config.path.empty() || config.path.filename().empty()) {
    return make_error(ErrorCode::InvalidArgument, "store path must name a file");
  }

  StoreInfo info;
  detail::DurableSection section;
  Result<std::unique_ptr<detail::StoreFile>> store =
      detail::StoreFile::open_writer(config, info, section);
  if (!store.ok()) {
    return store.error();
  }

  Result<detail::ResolvedModel> resolved =
      detail::resolve_model(section.state, config.limits, true);
  if (!resolved.ok()) {
    return resolved.error();
  }

  auto impl = std::make_unique<Impl>();
  impl->config = config;
  impl->info = info;
  impl->store = std::move(store.value());
  impl->writer_epoch = info.writer_epoch;
  impl->state = std::move(section.state);
  impl->current = std::make_shared<detail::SnapshotData>(
      detail::SnapshotData{std::move(resolved.value())});
  for (const FactRecord& fact : impl->state.facts) {
    impl->fact_keys.insert(detail::fact_key_of(fact));
  }
  for (const auto& [id, record] : impl->state.domains) {
    (void)id;
    impl->domain_keys.insert(DomainKey{record.domain_class, record.natural_key});
  }
  return std::unique_ptr<Registry>(new Registry(std::move(impl)));
}

Snapshot Registry::snapshot() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return Snapshot(impl_->current);
}

const StoreConfig& Registry::config() const noexcept { return impl_->config; }

const StoreInfo& Registry::store_info() const noexcept { return impl_->info; }

std::uint64_t Registry::generation() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->state.generation;
}

Digest Registry::digest() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->current->model.digest;
}

std::uint64_t Registry::writer_epoch() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->writer_epoch;
}

Status Registry::publish() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->publish();
}

#define FFD_LOCKED_CALL(method, request)      \
  std::lock_guard<std::mutex> guard(impl_->mutex); \
  return impl_->method(request)

Result<MutationOutcome> Registry::create_domain(const CreateDomainRequest& request) {
  FFD_LOCKED_CALL(create_domain, request);
}

Result<MutationOutcome> Registry::retire_domain(const RetireDomainRequest& request) {
  FFD_LOCKED_CALL(retire_domain, request);
}

Result<MutationOutcome> Registry::supersede_domain(const SupersedeDomainRequest& request) {
  FFD_LOCKED_CALL(supersede_domain, request);
}

Result<MutationOutcome> Registry::add_membership(const AddMembershipRequest& request) {
  FFD_LOCKED_CALL(add_membership, request);
}

Result<MutationOutcome> Registry::declare_alias(const DeclareAliasRequest& request) {
  FFD_LOCKED_CALL(declare_alias, request);
}

Result<MutationOutcome> Registry::declare_containment(const DeclareContainmentRequest& request) {
  FFD_LOCKED_CALL(declare_containment, request);
}

Result<MutationOutcome> Registry::declare_dependency(const DeclareDependencyRequest& request) {
  FFD_LOCKED_CALL(declare_dependency, request);
}

Result<MutationOutcome> Registry::declare_shared_fate(const DeclareSharedFateRequest& request) {
  FFD_LOCKED_CALL(declare_shared_fate, request);
}

Result<MutationOutcome> Registry::declare_independence(const DeclareIndependenceRequest& request) {
  FFD_LOCKED_CALL(declare_independence, request);
}

Result<MutationOutcome> Registry::revoke_claim(const RevokeClaimRequest& request) {
  FFD_LOCKED_CALL(revoke_claim, request);
}

Result<MutationOutcome> Registry::set_authority_precedence(
    const SetAuthorityPrecedenceRequest& request) {
  FFD_LOCKED_CALL(set_authority_precedence, request);
}

#undef FFD_LOCKED_CALL

Result<Snapshot> load_snapshot(const StoreConfig& config) {
  const Status limits_status = detail::validate_limits(config.limits);
  if (!limits_status.ok()) {
    return limits_status.error();
  }
  Result<detail::DurableSection> section = detail::StoreFile::read_file(config.path, config.limits);
  if (!section.ok()) {
    return section.error();
  }
  bool consistent = false;
  const std::uint64_t high_water = detail::epoch_high_water(config.path, &consistent);
  if (consistent && section.value().generation < high_water) {
    return make_error(ErrorCode::RollbackDetected,
                      "the store file is behind the durable epoch record");
  }
  Result<detail::ResolvedModel> resolved =
      detail::resolve_model(section.value().state, config.limits, true);
  if (!resolved.ok()) {
    return resolved.error();
  }
  return Snapshot(std::make_shared<detail::SnapshotData>(
      detail::SnapshotData{std::move(resolved.value())}));
}

}  // namespace ffd
