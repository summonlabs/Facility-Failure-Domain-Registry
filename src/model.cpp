// Facility Failure Domain Registry - DCCP boundary 49.
//
// Claim resolution. Every declared fact is evidence; the resolved model is the
// deterministic result of ranking that evidence by authority precedence,
// authority revision and retraction, with equal-authority contradictions
// preserved as conflicts instead of being silently resolved.
#include "model.hpp"

#include <algorithm>
#include <cstddef>
#include <deque>
#include <map>
#include <set>
#include <utility>

#include "canonical.hpp"
#include "checked.hpp"

namespace ffd::detail {
namespace {

[[nodiscard]] Error make_error(ErrorCode code, std::string detail) {
  return Error{code, std::move(detail)};
}

[[nodiscard]] Result<ResolvedModel> fail(bool loading, ErrorCode code, std::string detail) {
  if (loading) {
    return Error{ErrorCode::CorruptState, "durable state is not a valid model: " + detail};
  }
  return Error{code, std::move(detail)};
}

struct RetractionKey {
  SlotKey slot;
  AuthorityId target_authority;

  friend bool operator<(const RetractionKey& a, const RetractionKey& b) {
    if (a.slot < b.slot) return true;
    if (b.slot < a.slot) return false;
    return a.target_authority < b.target_authority;
  }
};

[[nodiscard]] FactEvidence evidence_of(const FactRecord& fact, FactStatus status,
                                       std::uint32_t precedence) {
  FactEvidence evidence;
  evidence.kind = fact.kind == FactKind::Retraction ? fact.target_kind : fact.kind;
  evidence.subject = fact.subject;
  evidence.object = fact.object;
  evidence.external = fact.external;
  evidence.target_authority = fact.target_authority;
  evidence.authority = fact.provenance.authority;
  evidence.authority_revision = fact.provenance.authority_revision;
  evidence.evidence = fact.provenance.evidence;
  evidence.status = status;
  evidence.precedence = precedence;
  return evidence;
}

[[nodiscard]] bool evidence_less(const FactEvidence& a, const FactEvidence& b) {
  if (a.kind != b.kind) return a.kind < b.kind;
  if (a.subject != b.subject) return a.subject < b.subject;
  if (a.object != b.object) return a.object < b.object;
  if (a.external != b.external) return a.external < b.external;
  if (a.target_authority != b.target_authority) return a.target_authority < b.target_authority;
  if (a.authority != b.authority) return a.authority < b.authority;
  if (a.authority_revision != b.authority_revision) return a.authority_revision < b.authority_revision;
  if (a.evidence != b.evidence) return a.evidence < b.evidence;
  return static_cast<std::uint8_t>(a.status) < static_cast<std::uint8_t>(b.status);
}

struct ClaimantGroup {
  AuthorityId authority;
  std::uint64_t max_revision{0};
  std::vector<const FactRecord*> records;
};

}  // namespace

std::uint32_t ModelState::precedence_of(const AuthorityId& authority) const noexcept {
  const auto it = precedence.find(authority);
  return it == precedence.end() ? kDefaultAuthorityPrecedence : it->second;
}

bool ModelState::has_natural_key(const DomainKey& key) const noexcept {
  for (const auto& [id, record] : domains) {
    (void)id;
    if (record.domain_class == key.domain_class && record.natural_key == key.natural_key) {
      return true;
    }
  }
  return false;
}

FactKey fact_key_of(const FactRecord& fact) noexcept {
  FactKey key;
  key.kind = fact.kind;
  key.target_kind = fact.target_kind;
  key.subject = fact.subject;
  key.object = fact.object;
  key.external = fact.external;
  key.external_target = fact.external_target;
  key.target_authority = fact.target_authority;
  key.authority = fact.provenance.authority;
  key.authority_revision = fact.provenance.authority_revision;
  return key;
}

SlotKey canonical_slot(FactKind kind, DomainId subject, DomainId object,
                       const ExternalRef& external) {
  SlotKey key;
  key.kind = kind;
  if (is_symmetric_fact_kind(kind)) {
    key.subject = subject < object ? subject : object;
    key.object = subject < object ? object : subject;
  } else {
    key.subject = subject;
    key.object = object;
  }
  const bool uses_external =
      is_external_fact_kind(kind) || (kind == FactKind::Dependency && !external.empty());
  if (uses_external) {
    key.external = external;
  }
  return key;
}

ClaimRef claim_ref_of(const SlotKey& key) {
  ClaimRef ref;
  ref.kind = key.kind;
  ref.target_kind = key.kind;
  ref.subject = key.subject;
  ref.object = key.object;
  ref.external = key.external;
  return ref;
}

bool canonical_fact_less(const FactRecord& a, const FactRecord& b) noexcept {
  if (a.kind != b.kind) return a.kind < b.kind;
  if (a.target_kind != b.target_kind) return a.target_kind < b.target_kind;
  if (a.subject != b.subject) return a.subject < b.subject;
  if (a.object != b.object) return a.object < b.object;
  if (a.external != b.external) return a.external < b.external;
  if (a.external_target != b.external_target) return a.external_target < b.external_target;
  if (a.target_authority != b.target_authority) return a.target_authority < b.target_authority;
  if (a.provenance.authority != b.provenance.authority) {
    return a.provenance.authority < b.provenance.authority;
  }
  if (a.provenance.authority_revision != b.provenance.authority_revision) {
    return a.provenance.authority_revision < b.provenance.authority_revision;
  }
  return a.provenance.evidence < b.provenance.evidence;
}

std::vector<const FactRecord*> canonical_fact_pointers(const ModelState& state) {
  std::vector<const FactRecord*> pointers;
  pointers.reserve(state.facts.size());
  for (const FactRecord& fact : state.facts) {
    pointers.push_back(&fact);
  }
  std::sort(pointers.begin(), pointers.end(),
            [](const FactRecord* a, const FactRecord* b) { return canonical_fact_less(*a, *b); });
  return pointers;
}

bool ResolvedModel::is_active(DomainId id) const noexcept {
  const auto it = lifecycle.find(id);
  return it != lifecycle.end() && it->second == DomainLifecycle::Active;
}

const DomainRecord* ResolvedModel::find_domain(DomainId id) const noexcept {
  const auto it = domain_index.find(id);
  if (it == domain_index.end()) {
    return nullptr;
  }
  return &domains[it->second];
}

std::size_t ResolvedModel::index_of(DomainId id) const noexcept {
  const auto it = domain_index.find(id);
  return it == domain_index.end() ? static_cast<std::size_t>(-1) : it->second;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------
Result<ResolvedModel> resolve_model(const ModelState& state, const Limits& limits, bool loading) {
  ResolvedModel model;
  model.generation = state.generation;
  model.limits = limits;

  // Domains, in identity order (std::map iteration order is the identity order).
  model.domains.reserve(state.domains.size());
  std::set<DomainKey> natural_keys;
  for (const auto& [id, record] : state.domains) {
    if (record.id.value > state.identity_high_water) {
      return fail(loading, ErrorCode::CorruptState,
                  "domain identity is beyond the identity high-water mark");
    }
    const DomainKey key{record.domain_class, record.natural_key};
    if (!natural_keys.insert(key).second) {
      return fail(loading, ErrorCode::DuplicateNaturalKey,
                  "duplicate domain natural key for class " +
                      std::string(to_string(record.domain_class)));
    }
    model.domain_index.emplace(id, model.domains.size());
    model.domains.push_back(record);
  }

  // Facts in canonical order; identities are session-local handles assigned in
  // that order and are deliberately absent from the content digest.
  std::vector<const FactRecord*> ordered = canonical_fact_pointers(state);
  model.facts.reserve(ordered.size());
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    FactRecord copy = *ordered[i];
    copy.id = static_cast<std::uint64_t>(i) + 1u;
    model.facts.push_back(std::move(copy));
  }

  // Structural validation of every reference.
  for (const FactRecord& fact : model.facts) {
    const SlotKey slot = canonical_slot(
        fact.kind == FactKind::Retraction ? fact.target_kind : fact.kind, fact.subject, fact.object,
        fact.external);
    if (model.domain_index.find(slot.subject) == model.domain_index.end()) {
      return fail(loading, ErrorCode::UnknownDomain, "claim subject domain does not exist");
    }
    if (slot.object.valid() && model.domain_index.find(slot.object) == model.domain_index.end()) {
      return fail(loading, ErrorCode::UnknownDomain, "claim object domain does not exist");
    }
    if (fact.kind == FactKind::Retraction &&
        model.domain_index.find(fact.subject) == model.domain_index.end()) {
      return fail(loading, ErrorCode::UnknownDomain, "retraction subject domain does not exist");
    }
  }

  // Group claims and retractions by slot.
  std::map<SlotKey, std::vector<const FactRecord*>> claims;
  std::map<RetractionKey, std::vector<const FactRecord*>> retractions;
  for (const FactRecord& fact : model.facts) {
    if (fact.kind == FactKind::Retraction) {
      RetractionKey key;
      key.slot = canonical_slot(fact.target_kind, fact.subject, fact.object, fact.external);
      key.target_authority = fact.target_authority;
      retractions[key].push_back(&fact);
    } else {
      claims[canonical_slot(fact.kind, fact.subject, fact.object, fact.external)].push_back(&fact);
    }
  }

  // Resolve every slot independently.
  for (const auto& [slot, records] : claims) {
    SlotResolution resolution;

    std::map<AuthorityId, ClaimantGroup> groups;
    for (const FactRecord* record : records) {
      ClaimantGroup& group = groups[record->provenance.authority];
      group.authority = record->provenance.authority;
      group.max_revision = std::max(group.max_revision, record->provenance.authority_revision);
      group.records.push_back(record);
    }

    std::map<AuthorityId, std::uint32_t> retraction_strength;
    std::map<AuthorityId, std::uint64_t> retraction_revision;
    std::map<AuthorityId, std::vector<const FactRecord*>> retraction_records;
    auto retraction_range = retractions.lower_bound(RetractionKey{slot, AuthorityId{}});
    for (auto it = retraction_range; it != retractions.end() && !(slot < it->first.slot); ++it) {
      const AuthorityId& claimant = it->first.target_authority;
      for (const FactRecord* record : it->second) {
        const std::uint32_t precedence = state.precedence_of(record->provenance.authority);
        std::uint32_t& best = retraction_strength[claimant];
        if (precedence > best) {
          best = precedence;
          retraction_revision[claimant] = record->provenance.authority_revision;
        } else if (precedence == best) {
          retraction_revision[claimant] =
              std::max(retraction_revision[claimant], record->provenance.authority_revision);
        }
        retraction_records[claimant].push_back(record);
      }
    }

    std::uint32_t top_claim_precedence = 0;
    for (const auto& [authority, group] : groups) {
      const std::uint32_t precedence = state.precedence_of(authority);
      const auto strength = retraction_strength.find(authority);
      const std::uint32_t retraction_best =
          strength == retraction_strength.end() ? 0u : strength->second;
      if (retraction_best <= precedence) {
        top_claim_precedence = std::max(top_claim_precedence, precedence);
      }
      (void)group;
    }

    bool conflicted = false;
    for (const auto& [authority, group] : groups) {
      (void)group;
      const std::uint32_t precedence = state.precedence_of(authority);
      const auto strength = retraction_strength.find(authority);
      const std::uint32_t retraction_best =
          strength == retraction_strength.end() ? 0u : strength->second;
      if (precedence == top_claim_precedence && retraction_best == precedence) {
        conflicted = true;
      }
    }

    bool any_effective_retraction = false;
    for (const auto& [authority, group] : groups) {
      const std::uint32_t precedence = state.precedence_of(authority);
      const auto strength = retraction_strength.find(authority);
      const std::uint32_t retraction_best =
          strength == retraction_strength.end() ? 0u : strength->second;

      for (const FactRecord* record : group.records) {
        FactStatus status = FactStatus::Effective;
        if (record->provenance.authority_revision < group.max_revision) {
          status = FactStatus::SupersededRevision;
        } else if (retraction_best > precedence) {
          status = FactStatus::Outranked;
        } else if (retraction_best == precedence && precedence == top_claim_precedence) {
          status = FactStatus::Conflicting;
        } else if (precedence < top_claim_precedence) {
          status = FactStatus::Outranked;
        } else if (precedence == 0) {
          status = FactStatus::Outranked;
        }
        if (status == FactStatus::Effective) {
          resolution.asserted = true;
        }
        if (status == FactStatus::Conflicting) {
          resolution.conflicted = true;
        }
        resolution.evidence.push_back(evidence_of(*record, status, precedence));
      }

      const auto records_it = retraction_records.find(authority);
      if (records_it != retraction_records.end()) {
        const std::uint64_t best_revision = retraction_revision[authority];
        for (const FactRecord* record : records_it->second) {
          const std::uint32_t precedence_of_retractor =
              state.precedence_of(record->provenance.authority);
          FactStatus status = FactStatus::Outranked;
          if (precedence_of_retractor < retraction_best) {
            status = FactStatus::Outranked;
          } else if (record->provenance.authority_revision < best_revision) {
            status = FactStatus::SupersededRevision;
          } else if (precedence_of_retractor > precedence) {
            status = FactStatus::Effective;
            any_effective_retraction = true;
          } else if (precedence_of_retractor == precedence &&
                     precedence == top_claim_precedence) {
            status = FactStatus::Conflicting;
          } else {
            status = FactStatus::Outranked;
          }
          if (status == FactStatus::Conflicting) {
            resolution.conflicted = true;
          }
          resolution.evidence.push_back(evidence_of(*record, status, precedence_of_retractor));
        }
      }
    }

    if (conflicted) {
      resolution.asserted = false;
      resolution.precedence = top_claim_precedence;
    } else if (resolution.asserted) {
      resolution.precedence = top_claim_precedence;
    } else if (any_effective_retraction) {
      resolution.retracted = true;
      std::uint32_t retracted_precedence = 0;
      for (const FactEvidence& evidence : resolution.evidence) {
        if (evidence.status == FactStatus::Effective) {
          retracted_precedence = std::max(retracted_precedence, evidence.precedence);
        }
      }
      resolution.precedence = retracted_precedence;
    }

    std::sort(resolution.evidence.begin(), resolution.evidence.end(), evidence_less);
    model.slots.emplace(slot, std::move(resolution));
  }

  // Lifecycle: retirement and supersession claims.
  for (const DomainRecord& record : model.domains) {
    model.lifecycle[record.id] = DomainLifecycle::Active;
  }
  std::map<DomainId, std::vector<const SlotKey*>> supersession_claims;
  for (const auto& [slot, resolution] : model.slots) {
    if (!resolution.asserted) {
      continue;
    }
    if (slot.kind == FactKind::Retirement) {
      if (model.lifecycle[slot.subject] == DomainLifecycle::Active) {
        model.lifecycle[slot.subject] = DomainLifecycle::Retired;
      }
    } else if (slot.kind == FactKind::Supersession) {
      supersession_claims[slot.subject].push_back(&slot);
    }
  }
  for (const auto& [predecessor, slots] : supersession_claims) {
    std::uint32_t best = 0;
    for (const SlotKey* slot : slots) {
      best = std::max(best, model.slots.at(*slot).precedence);
    }
    std::vector<const SlotKey*> top;
    for (const SlotKey* slot : slots) {
      if (model.slots.at(*slot).precedence == best) {
        top.push_back(slot);
      }
    }
    if (top.size() == 1) {
      model.successor[predecessor] = top.front()->object;
      model.lifecycle[predecessor] = DomainLifecycle::Superseded;
    } else {
      ConflictInfo conflict;
      conflict.kind = ConflictKind::Supersession;
      conflict.fact_kind = FactKind::Supersession;
      conflict.subject = predecessor;
      conflict.reason = "domain is claimed superseded by more than one successor";
      for (const SlotKey* slot : top) {
        for (const FactEvidence& evidence : model.slots.at(*slot).evidence) {
          if (evidence.status == FactStatus::Effective) {
            conflict.evidence.push_back(evidence);
          }
        }
      }
      std::sort(conflict.evidence.begin(), conflict.evidence.end(), evidence_less);
      model.conflicts.push_back(std::move(conflict));
    }
  }

  // Supersession chains must be acyclic and must terminate in an active domain.
  for (const auto& [predecessor, successor] : model.successor) {
    (void)successor;
    std::set<DomainId> seen;
    DomainId cursor = predecessor;
    while (true) {
      if (!seen.insert(cursor).second) {
        return fail(loading, ErrorCode::CycleNotAllowed, "supersession chain contains a cycle");
      }
      const auto next = model.successor.find(cursor);
      if (next == model.successor.end()) {
        break;
      }
      cursor = next->second;
    }
  }

  // Contradictory claims become conflicts when they concern the same subject and
  // the model has to choose. They are preserved, never silently resolved.
  for (const auto& [slot, resolution] : model.slots) {
    if (!resolution.conflicted) {
      continue;
    }
    std::map<AuthorityId, ConflictInfo> per_authority;
    for (const FactEvidence& evidence : resolution.evidence) {
      if (evidence.status != FactStatus::Conflicting) {
        continue;
      }
      AuthorityId key = evidence.target_authority.empty()
                            ? evidence.authority
                            : evidence.target_authority;
      ConflictInfo& conflict = per_authority[key];
      conflict.kind = ConflictKind::Claim;
      conflict.fact_kind = slot.kind;
      conflict.subject = slot.subject;
      conflict.object = slot.object;
      conflict.external = slot.external;
      conflict.target_authority = key;
      conflict.reason = "equal-precedence contradiction between a claim and a retraction";
    }
    for (const auto& [authority, conflict] : per_authority) {
      ConflictInfo copy = conflict;
      for (const FactEvidence& evidence : resolution.evidence) {
        const AuthorityId key =
            evidence.target_authority.empty() ? evidence.authority : evidence.target_authority;
        if (key == authority) {
          copy.evidence.push_back(evidence);
        }
      }
      model.conflicts.push_back(std::move(copy));
    }
  }

  // Membership and alias indexes.
  for (const auto& [slot, resolution] : model.slots) {
    if (!resolution.asserted) {
      continue;
    }
    if (slot.kind == FactKind::Membership) {
      model.members[slot.external].push_back(slot.subject);
    } else if (slot.kind == FactKind::ExternalAlias) {
      model.aliases[slot.external].push_back(slot.subject);
    }
  }
  for (auto& [ref, domains] : model.members) {
    (void)ref;
    std::sort(domains.begin(), domains.end());
    domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
  }
  for (auto& [ref, domains] : model.aliases) {
    (void)ref;
    std::sort(domains.begin(), domains.end());
    domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
  }

  // Effective exposure edges over active domains.
  for (const auto& [slot, resolution] : model.slots) {
    if (!resolution.asserted) {
      continue;
    }
    switch (slot.kind) {
      case FactKind::Containment: {
        if (!model.is_active(slot.subject) || !model.is_active(slot.object)) {
          break;
        }
        model.edges.push_back(EffectiveEdge{slot.subject, slot.object, resolution.precedence, slot});
        break;
      }
      case FactKind::Dependency: {
        if (!model.is_active(slot.subject)) {
          break;
        }
        if (slot.external.empty()) {
          if (!model.is_active(slot.object)) {
            UnresolvedReference unresolved;
            unresolved.state = ReferenceState::InactiveTarget;
            unresolved.dependent = slot.subject;
            unresolved.internal_target = slot.object;
            unresolved.evidence = resolution.evidence;
            model.unresolved.push_back(std::move(unresolved));
            break;
          }
          model.edges.push_back(EffectiveEdge{slot.object, slot.subject, resolution.precedence, slot});
        } else {
          const auto alias_it = model.aliases.find(slot.external);
          if (alias_it == model.aliases.end() || alias_it->second.empty()) {
            UnresolvedReference unresolved;
            unresolved.state = ReferenceState::NoAlias;
            unresolved.dependent = slot.subject;
            unresolved.target = slot.external;
            unresolved.evidence = resolution.evidence;
            model.unresolved.push_back(std::move(unresolved));
            break;
          }
          std::vector<DomainId> active_targets;
          for (const DomainId candidate : alias_it->second) {
            if (model.is_active(candidate)) {
              active_targets.push_back(candidate);
            }
          }
          if (active_targets.empty()) {
            UnresolvedReference unresolved;
            unresolved.state = ReferenceState::InactiveTarget;
            unresolved.dependent = slot.subject;
            unresolved.target = slot.external;
            unresolved.evidence = resolution.evidence;
            model.unresolved.push_back(std::move(unresolved));
            break;
          }
          if (active_targets.size() > 1) {
            UnresolvedReference unresolved;
            unresolved.state = ReferenceState::AmbiguousAlias;
            unresolved.dependent = slot.subject;
            unresolved.target = slot.external;
            unresolved.candidates = active_targets;
            unresolved.evidence = resolution.evidence;
            model.unresolved.push_back(std::move(unresolved));

            ConflictInfo conflict;
            conflict.kind = ConflictKind::AmbiguousAlias;
            conflict.fact_kind = FactKind::Dependency;
            conflict.subject = slot.subject;
            conflict.external = slot.external;
            conflict.reason = "several active domains claim the same external identity";
            conflict.evidence = resolution.evidence;
            model.conflicts.push_back(std::move(conflict));
            break;
          }
          model.edges.push_back(
              EffectiveEdge{active_targets.front(), slot.subject, resolution.precedence, slot});
        }
        break;
      }
      case FactKind::SharedFate: {
        if (!model.is_active(slot.subject) || !model.is_active(slot.object)) {
          break;
        }
        model.edges.push_back(EffectiveEdge{slot.subject, slot.object, resolution.precedence, slot});
        model.edges.push_back(EffectiveEdge{slot.object, slot.subject, resolution.precedence, slot});
        break;
      }
      default:
        break;
    }
  }
  std::sort(model.edges.begin(), model.edges.end(),
            [](const EffectiveEdge& a, const EffectiveEdge& b) {
              if (a.from != b.from) return a.from < b.from;
              if (a.to != b.to) return a.to < b.to;
              return a.source < b.source;
            });

  // Adjacency (deduplicated neighbours, ascending identity order).
  model.adjacency.assign(model.domains.size(), {});
  for (const EffectiveEdge& edge : model.edges) {
    const std::size_t from = model.index_of(edge.from);
    const std::size_t to = model.index_of(edge.to);
    if (from == static_cast<std::size_t>(-1) || to == static_cast<std::size_t>(-1)) {
      continue;
    }
    model.adjacency[from].push_back(static_cast<std::uint32_t>(to));
  }
  for (auto& neighbours : model.adjacency) {
    std::sort(neighbours.begin(), neighbours.end());
    neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
  }

  // Containment relation (enclosing -> enclosed), deduplicated.
  model.containment_adjacency.assign(model.domains.size(), {});
  for (const EffectiveEdge& edge : model.edges) {
    if (edge.source.kind != FactKind::Containment) {
      continue;
    }
    const std::size_t from = model.index_of(edge.from);
    const std::size_t to = model.index_of(edge.to);
    if (from == static_cast<std::size_t>(-1) || to == static_cast<std::size_t>(-1)) {
      continue;
    }
    model.containment_adjacency[from].push_back(static_cast<std::uint32_t>(to));
  }
  for (auto& neighbours : model.containment_adjacency) {
    std::sort(neighbours.begin(), neighbours.end());
    neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
  }

  // Containment must be acyclic. Iterative colouring DFS: deep graphs must not
  // consume stack proportional to depth.
  {
    std::vector<std::uint8_t> colour(model.domains.size(), 0);  // 0 new, 1 open, 2 closed
    std::vector<std::pair<std::uint32_t, std::size_t>> stack;
    for (std::uint32_t root = 0; root < model.domains.size(); ++root) {
      if (colour[root] != 0) {
        continue;
      }
      colour[root] = 1;
      stack.push_back({root, 0});
      while (!stack.empty()) {
        auto& [node, index] = stack.back();
        const std::vector<std::uint32_t>& neighbours = model.containment_adjacency[node];
        if (index < neighbours.size()) {
          const std::uint32_t next = neighbours[index];
          ++index;
          if (colour[next] == 1) {
            return fail(loading, ErrorCode::CycleNotAllowed,
                        "containment declarations form a cycle");
          }
          if (colour[next] == 0) {
            colour[next] = 1;
            stack.push_back({next, 0});
          }
        } else {
          colour[node] = 2;
          stack.pop_back();
        }
      }
    }
  }

  // Strongly connected components at the weakest precedence threshold (1).
  {
    const std::size_t count = model.domains.size();
    std::vector<std::vector<std::uint32_t>> reverse(count);
    for (std::size_t from = 0; from < count; ++from) {
      for (const std::uint32_t to : model.adjacency[from]) {
        reverse[to].push_back(static_cast<std::uint32_t>(from));
      }
    }
    std::vector<std::uint8_t> visited(count, 0);
    std::vector<std::uint32_t> order;
    order.reserve(count);
    std::vector<std::pair<std::uint32_t, std::size_t>> stack;
    for (std::uint32_t root = 0; root < count; ++root) {
      if (visited[root] != 0) {
        continue;
      }
      visited[root] = 1;
      stack.push_back({root, 0});
      while (!stack.empty()) {
        auto& [node, index] = stack.back();
        if (index < model.adjacency[node].size()) {
          const std::uint32_t next = model.adjacency[node][index];
          ++index;
          if (visited[next] == 0) {
            visited[next] = 1;
            stack.push_back({next, 0});
          }
        } else {
          order.push_back(node);
          stack.pop_back();
        }
      }
    }
    model.component.assign(count, 0);
    std::uint32_t component_id = 0;
    for (auto it = order.rbegin(); it != order.rend(); ++it) {
      const std::uint32_t root = *it;
      if (model.component[root] != 0) {
        continue;
      }
      ++component_id;
      model.component[root] = component_id;
      stack.push_back({root, 0});
      while (!stack.empty()) {
        const std::uint32_t node = stack.back().first;
        stack.pop_back();
        for (const std::uint32_t next : reverse[node]) {
          if (model.component[next] == 0) {
            model.component[next] = component_id;
            stack.push_back({next, 0});
          }
        }
      }
    }
  }

  model.digest = digest_of(encode_model_content(state));

  std::sort(model.conflicts.begin(), model.conflicts.end(),
            [](const ConflictInfo& a, const ConflictInfo& b) {
              if (a.kind != b.kind) return a.kind < b.kind;
              if (a.subject != b.subject) return a.subject < b.subject;
              if (a.object != b.object) return a.object < b.object;
              if (a.external != b.external) return a.external < b.external;
              if (a.fact_kind != b.fact_kind) return a.fact_kind < b.fact_kind;
              return a.target_authority < b.target_authority;
            });
  std::sort(model.unresolved.begin(), model.unresolved.end(),
            [](const UnresolvedReference& a, const UnresolvedReference& b) {
              if (a.state != b.state) return a.state < b.state;
              if (a.dependent != b.dependent) return a.dependent < b.dependent;
              if (a.target != b.target) return a.target < b.target;
              return a.internal_target < b.internal_target;
            });

  std::vector<FactEvidence> all_evidence;
  for (const auto& [slot, resolution] : model.slots) {
    (void)slot;
    all_evidence.insert(all_evidence.end(), resolution.evidence.begin(), resolution.evidence.end());
  }
  std::sort(all_evidence.begin(), all_evidence.end(), evidence_less);
  model.evidence = std::move(all_evidence);

  return model;
}

}  // namespace ffd::detail
