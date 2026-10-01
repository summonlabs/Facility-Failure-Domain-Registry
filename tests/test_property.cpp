// Facility Failure Domain Registry - randomized property tests against an
// independently written reference model.
//
// The reference model below deliberately uses different data structures and
// different algorithms from the library: dense linear scans instead of ordered
// slot maps, exhaustive threshold enumeration instead of a binary search, and
// freshly computed closures per threshold. Agreement is therefore evidence about
// the semantics rather than about shared code.
#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;
using ffd::FactKind;

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------
struct RefClaim {
  FactKind kind{FactKind::Membership};
  FactKind target_kind{FactKind::Membership};
  std::uint64_t subject{0};
  std::uint64_t object{0};
  bool external{false};
  std::string external_authority;
  std::string external_resource;
  std::string target_authority;
  std::string authority;
  std::uint64_t revision{0};
};

struct RefSlot {
  bool asserted{false};
  bool conflicted{false};
  std::uint32_t precedence{0};
};

struct RefEdge {
  FactKind kind{FactKind::Containment};
  std::uint64_t from{0};
  std::uint64_t to{0};
  std::uint32_t precedence{0};
};

struct RefDomain {
  std::uint64_t id{0};
  std::string key;
  ffd::DomainClass domain_class{ffd::DomainClass::Rack};
};

using Reach = std::map<std::uint64_t, std::set<std::uint64_t>>;

struct Resolved {
  std::map<std::uint64_t, int> lifecycle;  // 0 active, 1 retired, 2 superseded
  std::vector<RefEdge> edges;
  std::map<std::string, std::vector<std::uint64_t>> aliases;
  std::map<std::uint32_t, Reach> closures;  // by precedence threshold
  std::vector<std::uint64_t> active;
};

class Reference {
 public:
  std::vector<RefDomain> domains;
  std::vector<RefClaim> claims;
  std::map<std::string, std::uint32_t> precedence;
  std::uint64_t next_identity{1};

  [[nodiscard]] std::uint32_t precedence_of(const std::string& authority) const {
    const auto it = precedence.find(authority);
    return it == precedence.end() ? 1u : it->second;
  }

  [[nodiscard]] bool has_domain(std::uint64_t id) const {
    for (const RefDomain& domain : domains) {
      if (domain.id == id) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] bool key_exists(const std::string& key) const {
    for (const RefDomain& domain : domains) {
      if (domain.key == key) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] bool same_slot(const RefClaim& claim, FactKind kind, std::uint64_t subject,
                               std::uint64_t object, const std::string& external_authority,
                               const std::string& external_resource) const {
    return claim.kind == kind && claim.subject == subject && claim.object == object &&
           claim.external_authority == external_authority &&
           claim.external_resource == external_resource;
  }

  [[nodiscard]] RefSlot resolve_slot(FactKind kind, std::uint64_t subject, std::uint64_t object,
                                     const std::string& external_authority,
                                     const std::string& external_resource) const {
    std::map<std::string, std::uint64_t> claimants;
    for (const RefClaim& claim : claims) {
      if (claim.kind == FactKind::Retraction) {
        continue;
      }
      if (!same_slot(claim, kind, subject, object, external_authority, external_resource)) {
        continue;
      }
      auto& revision = claimants[claim.authority];
      revision = std::max(revision, claim.revision);
    }
    std::map<std::string, std::pair<std::uint32_t, std::uint64_t>> retractions;
    for (const RefClaim& claim : claims) {
      if (claim.kind != FactKind::Retraction || claim.target_kind != kind ||
          claim.subject != subject || claim.object != object ||
          claim.external_authority != external_authority ||
          claim.external_resource != external_resource) {
        continue;
      }
      const std::uint32_t strength = precedence_of(claim.authority);
      auto& entry = retractions[claim.target_authority];
      if (strength > entry.first) {
        entry = {strength, claim.revision};
      } else if (strength == entry.first) {
        entry.second = std::max(entry.second, claim.revision);
      }
    }
    std::set<std::string> survivors;
    for (const auto& entry : claimants) {
      const auto retraction = retractions.find(entry.first);
      const std::uint32_t strength =
          retraction == retractions.end() ? 0u : retraction->second.first;
      if (strength <= precedence_of(entry.first)) {
        survivors.insert(entry.first);
      }
    }
    std::uint32_t top = 0;
    for (const std::string& authority : survivors) {
      top = std::max(top, precedence_of(authority));
    }
    RefSlot slot;
    for (const std::string& authority : survivors) {
      const auto retraction = retractions.find(authority);
      const std::uint32_t strength =
          retraction == retractions.end() ? 0u : retraction->second.first;
      if (precedence_of(authority) == top && strength == top) {
        slot.conflicted = true;
      }
    }
    if (slot.conflicted) {
      slot.precedence = top;
      return slot;
    }
    if (top > 0) {
      slot.asserted = true;
      slot.precedence = top;
      return slot;
    }
    for (const auto& entry : retractions) {
      if (entry.second.first > precedence_of(entry.first)) {
        slot.precedence = std::max(slot.precedence, entry.second.first);
      }
    }
    return slot;
  }

  [[nodiscard]] Resolved resolve() const {
    Resolved resolved;
    for (const RefDomain& domain : domains) {
      resolved.lifecycle[domain.id] = 0;
    }
    for (const RefDomain& domain : domains) {
      if (resolve_slot(FactKind::Retirement, domain.id, 0, "", "").asserted) {
        resolved.lifecycle[domain.id] = 1;
      }
    }
    for (const RefDomain& subject : domains) {
      std::vector<std::pair<std::uint32_t, std::uint64_t>> successors;
      for (const RefDomain& candidate : domains) {
        const RefSlot slot =
            resolve_slot(FactKind::Supersession, subject.id, candidate.id, "", "");
        if (slot.asserted) {
          successors.emplace_back(slot.precedence, candidate.id);
        }
      }
      if (successors.empty()) {
        continue;
      }
      std::uint32_t best = 0;
      for (const auto& entry : successors) {
        best = std::max(best, entry.first);
      }
      std::size_t winners = 0;
      for (const auto& entry : successors) {
        if (entry.first == best) {
          ++winners;
        }
      }
      if (winners == 1) {
        resolved.lifecycle[subject.id] = 2;
      }
    }
    for (const RefDomain& domain : domains) {
      if (resolved.lifecycle[domain.id] == 0) {
        resolved.active.push_back(domain.id);
      }
    }
    std::sort(resolved.active.begin(), resolved.active.end());

    // Aliases first: external dependencies resolve through them.
    for (const RefClaim& claim : claims) {
      if (claim.kind != FactKind::ExternalAlias) {
        continue;
      }
      const RefSlot slot = resolve_slot(FactKind::ExternalAlias, claim.subject, 0,
                                        claim.external_authority, claim.external_resource);
      if (!slot.asserted || resolved.lifecycle[claim.subject] != 0) {
        continue;
      }
      std::vector<std::uint64_t>& ids =
          resolved.aliases[claim.external_authority + "|" + claim.external_resource];
      if (std::find(ids.begin(), ids.end(), claim.subject) == ids.end()) {
        ids.push_back(claim.subject);
      }
    }
    for (auto& entry : resolved.aliases) {
      std::sort(entry.second.begin(), entry.second.end());
    }

    const auto is_active = [&](std::uint64_t id) {
      return resolved.lifecycle.count(id) != 0 && resolved.lifecycle.at(id) == 0;
    };
    for (const RefClaim& claim : claims) {
      if (claim.kind == FactKind::Retraction || claim.kind == FactKind::Retirement ||
          claim.kind == FactKind::Supersession || claim.kind == FactKind::Membership ||
          claim.kind == FactKind::ExternalAlias) {
        continue;
      }
      const RefSlot slot = resolve_slot(claim.kind, claim.subject, claim.object,
                                        claim.external_authority, claim.external_resource);
      if (!slot.asserted) {
        continue;
      }
      switch (claim.kind) {
        case FactKind::Containment:
          if (is_active(claim.subject) && is_active(claim.object)) {
            resolved.edges.push_back(
                RefEdge{FactKind::Containment, claim.subject, claim.object, slot.precedence});
          }
          break;
        case FactKind::Dependency:
          if (!is_active(claim.subject)) {
            break;
          }
          if (claim.external) {
            const auto alias =
                resolved.aliases.find(claim.external_authority + "|" + claim.external_resource);
            if (alias == resolved.aliases.end() || alias->second.size() != 1) {
              break;
            }
            if (is_active(alias->second.front())) {
              resolved.edges.push_back(
                  RefEdge{FactKind::Dependency, alias->second.front(), claim.subject,
                          slot.precedence});
            }
          } else if (is_active(claim.object)) {
            resolved.edges.push_back(
                RefEdge{FactKind::Dependency, claim.object, claim.subject, slot.precedence});
          }
          break;
        case FactKind::SharedFate:
          if (is_active(claim.subject) && is_active(claim.object)) {
            resolved.edges.push_back(
                RefEdge{FactKind::SharedFate, claim.subject, claim.object, slot.precedence});
            resolved.edges.push_back(
                RefEdge{FactKind::SharedFate, claim.object, claim.subject, slot.precedence});
          }
          break;
        default:
          break;
      }
    }

    std::set<std::uint32_t> thresholds;
    thresholds.insert(0);
    for (const RefEdge& edge : resolved.edges) {
      thresholds.insert(edge.precedence);
    }
    for (const std::uint32_t threshold : thresholds) {
      Reach closure;
      std::map<std::uint64_t, std::set<std::uint64_t>> adjacency;
      for (const std::uint64_t id : resolved.active) {
        closure[id] = {id};
        adjacency[id] = {};
      }
      for (const RefEdge& edge : resolved.edges) {
        if (edge.precedence < threshold) {
          continue;
        }
        if (adjacency.count(edge.from) == 0 || adjacency.count(edge.to) == 0) {
          continue;
        }
        adjacency[edge.from].insert(edge.to);
      }
      for (const std::uint64_t id : resolved.active) {
        std::vector<std::uint64_t> pending{id};
        while (!pending.empty()) {
          const std::uint64_t node = pending.back();
          pending.pop_back();
          for (const std::uint64_t next : adjacency[node]) {
            if (closure[id].insert(next).second) {
              pending.push_back(next);
            }
          }
        }
      }
      resolved.closures[threshold] = std::move(closure);
    }
    return resolved;
  }
};

[[nodiscard]] std::set<std::uint64_t> upstream_of(const Resolved& resolved,
                                                  std::uint64_t target) {
  std::set<std::uint64_t> result;
  const Reach& reach = resolved.closures.at(0);
  for (const auto& entry : reach) {
    if (entry.first != target && entry.second.count(target) != 0) {
      result.insert(entry.first);
    }
  }
  return result;
}

[[nodiscard]] std::set<std::uint64_t> downstream_of(const Resolved& resolved,
                                                    std::uint64_t target) {
  std::set<std::uint64_t> result;
  const Reach& reach = resolved.closures.at(0);
  const auto it = reach.find(target);
  if (it == reach.end()) {
    return result;
  }
  for (const std::uint64_t id : it->second) {
    if (id != target) {
      result.insert(id);
    }
  }
  return result;
}

[[nodiscard]] std::set<std::uint64_t> shared_fate_of(const Resolved& resolved,
                                                     std::uint64_t target) {
  std::set<std::uint64_t> result;
  const Reach& reach = resolved.closures.at(0);
  const auto self = reach.find(target);
  if (self == reach.end()) {
    return result;
  }
  for (const auto& entry : reach) {
    if (entry.first == target) {
      continue;
    }
    if (self->second.count(entry.first) != 0 && entry.second.count(target) != 0) {
      result.insert(entry.first);
    }
  }
  return result;
}

[[nodiscard]] std::uint32_t shared_fate_strength(const Resolved& resolved, std::uint64_t a,
                                                 std::uint64_t b) {
  std::uint32_t best = 0;
  for (const auto& entry : resolved.closures) {
    if (entry.first == 0) {
      continue;
    }
    const auto from = entry.second.find(a);
    const auto to = entry.second.find(b);
    if (from == entry.second.end() || to == entry.second.end()) {
      continue;
    }
    if (from->second.count(b) != 0 && to->second.count(a) != 0) {
      best = std::max(best, entry.first);
    }
  }
  return best;
}

[[nodiscard]] bool equal_ids(const std::vector<DomainId>& actual,
                             const std::set<std::uint64_t>& expected) {
  if (actual.size() != expected.size()) {
    return false;
  }
  std::size_t index = 0;
  for (const std::uint64_t value : expected) {
    if (actual[index].value != value) {
      return false;
    }
    ++index;
  }
  return true;
}

[[nodiscard]] std::string join_ids(const std::vector<DomainId>& values) {
  std::string out;
  for (const DomainId id : values) {
    out += std::to_string(id.value);
    out += ",";
  }
  return out;
}

[[nodiscard]] std::string join_values(const std::set<std::uint64_t>& values) {
  std::string out;
  for (const std::uint64_t value : values) {
    out += std::to_string(value);
    out += ",";
  }
  return out;
}

}  // namespace

namespace {

using ffd::DomainId;

struct Runner {
  ffdtest::ScratchDir scratch;
  std::unique_ptr<ffd::Registry> registry;
  Reference reference;
  std::uint64_t seed{0};
  std::uint64_t counter{0};
  std::uint64_t accepted{0};
  std::uint64_t operation{0};

  Runner(std::uint64_t seed_value, const std::string& label)
      : scratch(label), seed(seed_value) {
    ffd::StoreConfig config;
    config.path = scratch.file("store.ffdr");
    config.durability = ffd::Durability::DurablePerMutation;
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::move(opened.value());
  }

  [[nodiscard]] std::string next_key(const std::string& prefix) {
    return prefix + "-" + std::to_string(seed) + "-" + std::to_string(++counter);
  }

  void fail(const std::string& context, const std::string& message) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              "seed=" + std::to_string(seed) + " op=" +
                                  std::to_string(operation) + " accepted=" +
                                  std::to_string(accepted) + " [" + context + "] " + message);
    throw ::ffdtest::AssertionFailure{message};
  }
};

// Independent re-derivation of every published answer, compared field by field.
void verify(Runner& runner, ffdtest::Rng& rng, const std::string& context) {
  const ffd::Snapshot snapshot = runner.registry->snapshot();
  const Reference& reference = runner.reference;
  const Resolved resolved = reference.resolve();

  if (snapshot.domain_count() != reference.domains.size()) {
    runner.fail(context, "domain count " + std::to_string(snapshot.domain_count()) +
                             " but the reference has " +
                             std::to_string(reference.domains.size()));
  }
  if (snapshot.fact_count() != reference.claims.size()) {
    runner.fail(context, "fact count " + std::to_string(snapshot.fact_count()) +
                             " but the reference has " +
                             std::to_string(reference.claims.size()));
  }
  if (snapshot.generation() != runner.accepted) {
    runner.fail(context, "generation " + std::to_string(snapshot.generation()) +
                             " but " + std::to_string(runner.accepted) +
                             " operations were accepted");
  }
  for (const RefDomain& domain : reference.domains) {
    const ffd::Result<ffd::DomainInfo> info = snapshot.domain(DomainId{domain.id});
    if (!info.ok()) {
      runner.fail(context, "domain " + std::to_string(domain.id) + " is missing");
    }
    if (info.value().natural_key != domain.key) {
      runner.fail(context, "domain key mismatch");
    }
    const int expected_lifecycle = resolved.lifecycle.at(domain.id);
    const int actual_lifecycle = info.value().lifecycle == ffd::DomainLifecycle::Active
                                     ? 0
                                     : (info.value().lifecycle == ffd::DomainLifecycle::Retired ? 1
                                                                                                : 2);
    if (expected_lifecycle != actual_lifecycle) {
      runner.fail(context, "lifecycle of #" + std::to_string(domain.id) + " is " +
                               std::to_string(actual_lifecycle) + " but the reference says " +
                               std::to_string(expected_lifecycle));
    }
  }
  const std::vector<std::uint64_t> active = resolved.active;
  for (const std::uint64_t id : active) {
    const ffd::Result<std::vector<DomainId>> upstream =
        snapshot.upstream_exposure(DomainId{id});
    if (!upstream.ok() || !equal_ids(upstream.value(), upstream_of(resolved, id))) {
      runner.fail(context, "upstream exposure of " + std::to_string(id) + " is [" +
                               join_ids(upstream.ok() ? upstream.value()
                                                      : std::vector<DomainId>{}) +
                               "] but the reference says [" +
                               join_values(upstream_of(resolved, id)) + "]");
    }
    const ffd::Result<std::vector<DomainId>> downstream =
        snapshot.downstream_exposure(DomainId{id});
    if (!downstream.ok() || !equal_ids(downstream.value(), downstream_of(resolved, id))) {
      runner.fail(context, "downstream exposure of " + std::to_string(id) + " is [" +
                               join_ids(downstream.ok() ? downstream.value()
                                                        : std::vector<DomainId>{}) +
                               "] but the reference says [" +
                               join_values(downstream_of(resolved, id)) + "]");
    }
    const ffd::Result<std::vector<DomainId>> group = snapshot.shared_fate_group(DomainId{id});
    if (!group.ok() || !equal_ids(group.value(), shared_fate_of(resolved, id))) {
      runner.fail(context, "shared fate group of " + std::to_string(id) + " is [" +
                               join_ids(group.ok() ? group.value() : std::vector<DomainId>{}) +
                               "] but the reference says [" + join_values(shared_fate_of(resolved, id)) +
                               "]");
    }
  }

  // Pair verdicts: exhaustive on small models, sampled otherwise.
  std::vector<std::pair<std::uint64_t, std::uint64_t>> pairs;
  if (active.size() <= 8) {
    for (std::size_t i = 0; i < active.size(); ++i) {
      for (std::size_t j = i + 1; j < active.size(); ++j) {
        pairs.emplace_back(active[i], active[j]);
      }
    }
  } else {
    for (int sample = 0; sample < 6; ++sample) {
      const std::uint64_t a = active[rng.below(static_cast<std::uint32_t>(active.size()))];
      const std::uint64_t b = active[rng.below(static_cast<std::uint32_t>(active.size()))];
      if (a != b) {
        pairs.emplace_back(std::min(a, b), std::max(a, b));
      }
    }
  }
  for (const auto& pair : pairs) {
    const ffd::Result<ffd::PairVerdictResult> verdict =
        snapshot.pair_verdict(DomainId{pair.first}, DomainId{pair.second});
    if (!verdict.ok()) {
      runner.fail(context, "pair verdict query failed");
    }
    const std::uint32_t strength = shared_fate_strength(resolved, pair.first, pair.second);
    const RefSlot independence =
        reference.resolve_slot(FactKind::Independence, pair.first, pair.second, "", "");
    const std::uint32_t independence_precedence =
        independence.asserted ? independence.precedence : 0;
    ffd::PairVerdict expected = ffd::PairVerdict::Unknown;
    if (strength >= 1 && independence_precedence > 0) {
      expected = strength > independence_precedence
                     ? ffd::PairVerdict::ProvenSharedFate
                     : (strength == independence_precedence ? ffd::PairVerdict::Conflicting
                                                            : ffd::PairVerdict::ProvenIndependent);
    } else if (strength >= 1) {
      expected = ffd::PairVerdict::ProvenSharedFate;
    } else if (independence_precedence > 0) {
      expected = ffd::PairVerdict::ProvenIndependent;
    }
    if (verdict.value().verdict != expected) {
      runner.fail(context, "verdict for " + std::to_string(pair.first) + "/" +
                               std::to_string(pair.second) + " is " +
                               ffd::to_string(verdict.value().verdict) + " but the reference says " +
                               ffd::to_string(expected));
    }
    if (verdict.value().shared_fate_strength != strength) {
      runner.fail(context, "shared fate strength mismatch for " +
                               std::to_string(pair.first));
    }
    if (verdict.value().independence_precedence != independence_precedence) {
      runner.fail(context, "independence precedence mismatch for " +
                               std::to_string(pair.first));
    }
  }

  // Membership answers for every resource the model mentions.
  std::set<std::string> resources;
  for (const RefClaim& claim : reference.claims) {
    if (claim.kind == FactKind::Membership) {
      resources.insert(claim.external_authority + "|" + claim.external_resource);
    }
  }
  for (const std::string& resource : resources) {
    const std::size_t separator = resource.find('|');
    const ffd::ExternalRef ref =
        ffdtest::external(resource.substr(0, separator).c_str(), resource.substr(separator + 1));
    const ffd::Result<std::vector<DomainId>> containing = snapshot.containing_domains(ref);
    if (!containing.ok()) {
      runner.fail(context, "containing domains query failed");
    }
    std::set<std::uint64_t> expected;
    for (const RefClaim& claim : reference.claims) {
      if (claim.kind != FactKind::Membership) {
        continue;
      }
      if (claim.external_authority + "|" + claim.external_resource != resource) {
        continue;
      }
      const RefSlot slot = reference.resolve_slot(FactKind::Membership, claim.subject, 0,
                                                  claim.external_authority,
                                                  claim.external_resource);
      const auto lifecycle = resolved.lifecycle.find(claim.subject);
      if (slot.asserted && lifecycle != resolved.lifecycle.end() && lifecycle->second == 0) {
        expected.insert(claim.subject);
      }
    }
    if (!equal_ids(containing.value(), expected)) {
      runner.fail(context, "containing domains of " + resource + " are [" +
                               join_ids(containing.value()) + "] but the reference says [" +
                               join_values(expected) + "]");
    }
  }
}

struct Prediction {
  bool accept{true};
  std::string error;
};

// Expected outcome of a single-claim declaration, derived only from the
// reference state.
[[nodiscard]] Prediction predict_claim(const Reference& reference, const Resolved& resolved,
                                       std::uint64_t subject, std::uint64_t object,
                                       const std::string& authority, std::uint64_t revision,
                                       FactKind kind, bool external,
                                       const std::string& external_authority,
                                       const std::string& external_resource) {
  Prediction prediction;
  const auto lifecycle = [&](std::uint64_t id) {
    const auto it = resolved.lifecycle.find(id);
    return it == resolved.lifecycle.end() ? -1 : it->second;
  };
  // The declaring domain is validated completely before the referenced one, so a
  // declaration that names both an unknown identity and an inactive domain is
  // diagnosed on the declaring side first.
  if (!reference.has_domain(subject)) {
    prediction.accept = false;
    prediction.error = "unknown_domain";
    return prediction;
  }
  if (lifecycle(subject) != 0) {
    prediction.accept = false;
    prediction.error = "domain_not_active";
    return prediction;
  }
  if (!external && object != 0) {
    if (!reference.has_domain(object)) {
      prediction.accept = false;
      prediction.error = "unknown_domain";
      return prediction;
    }
    if (lifecycle(object) != 0) {
      prediction.accept = false;
      prediction.error = "domain_not_active";
      return prediction;
    }
  }
  for (const RefClaim& claim : reference.claims) {
    if (claim.kind != kind || claim.subject != subject || claim.object != object ||
        claim.external != external || claim.external_authority != external_authority ||
        claim.external_resource != external_resource || claim.authority != authority ||
        claim.revision != revision) {
      continue;
    }
    prediction.accept = false;
    prediction.error = "duplicate_claim";
    return prediction;
  }
  return prediction;
}

void finish_op(Runner& runner, ffdtest::Rng& rng,
               const ffd::Result<ffd::MutationOutcome>& result, const Prediction& prediction,
               const std::string& context, const std::function<void()>& apply) {
  if (prediction.accept) {
    if (!result.ok()) {
      runner.fail(context, "expected acceptance, got " +
                               std::string(ffd::to_string(result.code())) + ": " +
                               result.error().detail);
    }
    apply();
    ++runner.accepted;
  } else {
    if (result.ok()) {
      runner.fail(context, "expected refusal (" + prediction.error +
                               ") but the mutation was accepted");
    }
    if (!prediction.error.empty() &&
        std::string(ffd::to_string(result.code())) != prediction.error) {
      runner.fail(context, "expected " + prediction.error + ", got " +
                               ffd::to_string(result.code()));
    }
  }
  verify(runner, rng, context);
}

[[nodiscard]] bool reference_has_containment_cycle(const Reference& reference) {
  const Resolved resolved = reference.resolve();
  std::map<std::uint64_t, std::set<std::uint64_t>> adjacency;
  for (const RefEdge& edge : resolved.edges) {
    if (edge.kind == FactKind::Containment) {
      adjacency[edge.from].insert(edge.to);
    }
  }
  std::map<std::uint64_t, int> colour;
  for (const auto& entry : adjacency) {
    colour[entry.first] = 0;
    for (const std::uint64_t to : entry.second) {
      colour[to] = 0;
    }
  }
  for (const auto& entry : colour) {
    if (entry.second != 0) {
      continue;
    }
    std::vector<std::pair<std::uint64_t, std::size_t>> stack;
    colour[entry.first] = 1;
    stack.push_back({entry.first, 0});
    while (!stack.empty()) {
      auto& frame = stack.back();
      const std::set<std::uint64_t>& neighbours = adjacency[frame.first];
      if (frame.second < neighbours.size()) {
        auto it = neighbours.begin();
        std::advance(it, static_cast<std::ptrdiff_t>(frame.second));
        const std::uint64_t next = *it;
        ++frame.second;
        if (colour[next] == 1) {
          return true;
        }
        if (colour[next] == 0) {
          colour[next] = 1;
          stack.push_back({next, 0});
        }
      } else {
        colour[frame.first] = 2;
        stack.pop_back();
      }
    }
  }
  return false;
}

[[nodiscard]] std::uint64_t reference_successor(const Reference& reference,
                                                std::uint64_t subject) {
  const Resolved resolved = reference.resolve();
  const auto it = resolved.lifecycle.find(subject);
  if (it == resolved.lifecycle.end() || it->second != 2) {
    return 0;
  }
  for (const RefDomain& candidate : reference.domains) {
    if (reference.resolve_slot(FactKind::Supersession, subject, candidate.id, "", "").asserted) {
      return candidate.id;
    }
  }
  return 0;
}

[[nodiscard]] bool reference_has_supersession_cycle(const Reference& reference) {
  for (const RefDomain& domain : reference.domains) {
    std::set<std::uint64_t> seen;
    std::uint64_t cursor = domain.id;
    while (cursor != 0) {
      if (!seen.insert(cursor).second) {
        return true;
      }
      cursor = reference_successor(reference, cursor);
    }
  }
  return false;
}

void run_state_machine(std::uint64_t seed, int operations, bool conflict_heavy) {
  Runner runner(seed, "property-" + std::to_string(seed));
  ffdtest::Rng rng(seed);
  const char* authorities[3] = {"authority.alpha", "authority.beta", "authority.gamma"};

  for (int step = 0; step < operations; ++step) {
    runner.operation = static_cast<std::uint64_t>(step);
    const Resolved resolved = runner.reference.resolve();
    const auto active_of = [&](std::uint64_t id) {
      const auto it = resolved.lifecycle.find(id);
      return it != resolved.lifecycle.end() && it->second == 0;
    };
    const auto pick = [&]() -> std::uint64_t {
      if (runner.reference.domains.empty()) {
        // A well-formed but unknown identity: identity 0 is never assignable and
        // is rejected earlier, by argument validation.
        return 900000 + rng.below(50);
      }
      const std::uint32_t roll = rng.below(100);
      if (roll < 12) {
        return 900000 + rng.below(50);
      }
      return runner.reference.domains[rng.below(
                                          static_cast<std::uint32_t>(runner.reference.domains.size()))]
          .id;
    };
    const std::string authority = authorities[rng.below(3)];
    const std::uint64_t revision = 1 + rng.below(3);
    const std::uint32_t roll = rng.below(100);

    if (roll < 20) {
      const std::string key = runner.next_key("domain");
      const ffd::DomainClass domain_class =
          static_cast<ffd::DomainClass>(1 + rng.below(10));
      ffd::CreateDomainRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.domain_class = domain_class;
      request.natural_key = key;
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->create_domain(request);
      const std::string context = "create " + key;
      if (runner.reference.key_exists(key)) {
        if (result.ok()) {
          runner.fail(context, "duplicate natural key was accepted");
        }
        if (result.code() != ffd::ErrorCode::DuplicateNaturalKey) {
          runner.fail(context, std::string("expected duplicate_natural_key, got ") +
                                   ffd::to_string(result.code()));
        }
        verify(runner, rng, context);
        continue;
      }
      if (!result.ok()) {
        runner.fail(context, "create was refused: " + result.error().detail);
      }
      RefDomain domain;
      domain.id = runner.reference.next_identity++;
      domain.key = key;
      domain.domain_class = domain_class;
      runner.reference.domains.push_back(domain);
      ++runner.accepted;
      verify(runner, rng, context);
      continue;
    }

    if (roll < 34) {
      const std::uint64_t domain = pick();
      const std::string resource = "asset-" + std::to_string(rng.below(6));
      ffd::AddMembershipRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.domain = DomainId{domain};
      request.resource = ffdtest::external("asset.registry", resource);
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->add_membership(request);
      const std::string context = "membership " + std::to_string(domain) + "/" + resource;
      const Prediction prediction =
          predict_claim(runner.reference, resolved, domain, 0, authority, revision,
                        FactKind::Membership, true, "asset.registry", resource);
      finish_op(runner, rng, result, prediction, context, [&] {
                  RefClaim claim;
                  claim.kind = FactKind::Membership;
                  claim.subject = domain;
                  claim.external = true;
                  claim.external_authority = "asset.registry";
                  claim.external_resource = resource;
                  claim.authority = authority;
                  claim.revision = revision;
                  runner.reference.claims.push_back(claim);
                });
      continue;
    }

    if (roll < 42) {
      const std::uint64_t domain = pick();
      const std::string resource = "identity-" + std::to_string(rng.below(6));
      ffd::DeclareAliasRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.domain = DomainId{domain};
      request.resource = ffdtest::external("dccp.topology", resource);
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->declare_alias(request);
      const std::string context = "alias " + std::to_string(domain) + "/" + resource;
      const Prediction prediction =
          predict_claim(runner.reference, resolved, domain, 0, authority, revision,
                        FactKind::ExternalAlias, true, "dccp.topology", resource);
      finish_op(runner, rng, result, prediction, context, [&] {
        RefClaim claim;
        claim.kind = FactKind::ExternalAlias;
        claim.subject = domain;
        claim.external = true;
        claim.external_authority = "dccp.topology";
        claim.external_resource = resource;
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 54) {
      const std::uint64_t parent = pick();
      const std::uint64_t child = pick();
      ffd::DeclareContainmentRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.parent = DomainId{parent};
      request.child = DomainId{child};
      const ffd::Result<ffd::MutationOutcome> result =
          runner.registry->declare_containment(request);
      const std::string context =
          "containment " + std::to_string(parent) + "/" + std::to_string(child);
      Prediction prediction;
      if (parent == child) {
        prediction.accept = false;
        prediction.error = "self_reference";
      } else {
        prediction = predict_claim(runner.reference, resolved, parent, child, authority, revision,
                                   FactKind::Containment, false, "", "");
        if (prediction.accept) {
          RefClaim probe;
          probe.kind = FactKind::Containment;
          probe.subject = parent;
          probe.object = child;
          probe.authority = authority;
          probe.revision = revision;
          runner.reference.claims.push_back(probe);
          const bool cyclic = reference_has_containment_cycle(runner.reference);
          runner.reference.claims.pop_back();
          if (cyclic) {
            prediction.accept = false;
            prediction.error = "cycle_not_allowed";
          }
        }
      }
      finish_op(runner, rng, result, prediction, context, [&] {
        RefClaim claim;
        claim.kind = FactKind::Containment;
        claim.subject = parent;
        claim.object = child;
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 64) {
      const std::uint64_t dependent = pick();
      const bool external = rng.chance(1, 4);
      const std::uint64_t target = pick();
      const std::string resource = "ups-" + std::to_string(rng.below(4));
      ffd::DeclareDependencyRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.dependent = DomainId{dependent};
      if (external) {
        request.external_target = ffdtest::external("dccp.topology", resource);
      } else {
        request.target = DomainId{target};
      }
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->declare_dependency(request);
      const std::string context = "dependency " + std::to_string(dependent);
      Prediction prediction;
      if (!external && dependent == target) {
        prediction.accept = false;
        prediction.error = "self_reference";
      } else {
        prediction =
            predict_claim(runner.reference, resolved, dependent, external ? 0 : target, authority,
                          revision, FactKind::Dependency, external, "dccp.topology", resource);
      }
      finish_op(runner, rng, result, prediction, context, [&] {
        RefClaim claim;
        claim.kind = FactKind::Dependency;
        claim.subject = dependent;
        if (external) {
          claim.external = true;
          claim.external_authority = "dccp.topology";
          claim.external_resource = resource;
        } else {
          claim.object = target;
        }
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 74 || (conflict_heavy && roll < 84)) {
      const std::uint64_t a = pick();
      const std::uint64_t b = pick();
      const bool shared = (roll % 2) == 0;
      ffd::DeclareSharedFateRequest shared_request;
      ffd::DeclareIndependenceRequest independent_request;
      ffd::Result<ffd::MutationOutcome> result = ffd::Error{ffd::ErrorCode::Ok, ""};
      if (shared) {
        shared_request.context =
            ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
        shared_request.a = DomainId{a};
        shared_request.b = DomainId{b};
        result = runner.registry->declare_shared_fate(shared_request);
      } else {
        independent_request.context =
            ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
        independent_request.a = DomainId{a};
        independent_request.b = DomainId{b};
        result = runner.registry->declare_independence(independent_request);
      }
      const std::string context = std::string(shared ? "shared_fate " : "independence ") +
                                  std::to_string(a) + "/" + std::to_string(b);
      Prediction prediction;
      if (a == b) {
        prediction.accept = false;
        prediction.error = "self_reference";
      } else {
        prediction = predict_claim(runner.reference, resolved, std::min(a, b), std::max(a, b),
                                   authority, revision,
                                   shared ? FactKind::SharedFate : FactKind::Independence, false,
                                   "", "");
      }
      finish_op(runner, rng, result, prediction, context, [&] {
        RefClaim claim;
        claim.kind = shared ? FactKind::SharedFate : FactKind::Independence;
        claim.subject = std::min(a, b);
        claim.object = std::max(a, b);
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 79) {
      const std::uint64_t domain = pick();
      ffd::RetireDomainRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.domain = DomainId{domain};
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->retire_domain(request);
      const std::string context = "retire " + std::to_string(domain);
      Prediction prediction = predict_claim(runner.reference, resolved, domain, 0, authority,
                                           revision, FactKind::Retirement, false, "", "");
      if (!prediction.accept && prediction.error == "domain_not_active") {
        prediction.error = "already_retired";
      }
      finish_op(runner, rng, result, prediction, context, [&] {
        RefClaim claim;
        claim.kind = FactKind::Retirement;
        claim.subject = domain;
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 84) {
      const std::uint64_t predecessor = pick();
      const std::string key = runner.next_key("replacement");
      const ffd::DomainClass domain_class = static_cast<ffd::DomainClass>(1 + rng.below(10));
      ffd::SupersedeDomainRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.predecessor = DomainId{predecessor};
      request.domain_class = domain_class;
      request.natural_key = key;
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->supersede_domain(request);
      const std::string context = "supersede " + std::to_string(predecessor);
      std::string error;
      bool expected_accept = true;
      if (!runner.reference.has_domain(predecessor)) {
        expected_accept = false;
        error = "unknown_domain";
      } else if (runner.reference.key_exists(key)) {
        expected_accept = false;
        error = "duplicate_natural_key";
      } else {
        RefDomain domain;
        domain.id = runner.reference.next_identity;
        domain.key = key;
        domain.domain_class = domain_class;
        runner.reference.domains.push_back(domain);
        RefClaim claim;
        claim.kind = FactKind::Supersession;
        claim.subject = predecessor;
        claim.object = domain.id;
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
        if (reference_has_supersession_cycle(runner.reference)) {
          expected_accept = false;
          error = "cycle_not_allowed";
        }
        runner.reference.claims.pop_back();
        runner.reference.domains.pop_back();
      }
      Prediction prediction;
      prediction.accept = expected_accept;
      prediction.error = error;
      finish_op(runner, rng, result, prediction, context, [&] {
        RefDomain domain;
        domain.id = runner.reference.next_identity++;
        domain.key = key;
        domain.domain_class = domain_class;
        runner.reference.domains.push_back(domain);
        RefClaim claim;
        claim.kind = FactKind::Supersession;
        claim.subject = predecessor;
        claim.object = domain.id;
        claim.authority = authority;
        claim.revision = revision;
        runner.reference.claims.push_back(claim);
      });
      continue;
    }

    if (roll < 98) {
      // Revoke a claim that the reference already holds.
      std::vector<std::size_t> revocable;
      for (std::size_t index = 0; index < runner.reference.claims.size(); ++index) {
        const RefClaim& claim = runner.reference.claims[index];
        if (claim.kind == FactKind::Retraction || claim.kind == FactKind::Retirement ||
            claim.kind == FactKind::Supersession) {
          continue;
        }
        if (!active_of(claim.subject)) {
          continue;
        }
        if (!claim.external && !active_of(claim.object)) {
          continue;
        }
        revocable.push_back(index);
      }
      if (revocable.empty()) {
        continue;
      }
      const RefClaim target = runner.reference.claims[revocable[rng.below(
          static_cast<std::uint32_t>(revocable.size()))]];
      const bool matches = rng.chance(4, 5);
      ffd::ClaimRef claim_ref;
      claim_ref.kind = target.kind;
      claim_ref.target_kind = target.kind;
      claim_ref.subject = DomainId{target.subject};
      claim_ref.object = DomainId{target.object};
      claim_ref.external.authority = ffdtest::authority(target.external_authority.c_str());
      claim_ref.external.resource.value = target.external_resource;
      claim_ref.target_authority = ffdtest::authority(
          matches ? target.authority.c_str() : "authority.absent");
      ffd::RevokeClaimRequest request;
      request.context = ffdtest::make_context(authority.c_str(), revision, runner.next_key("key"));
      request.claim = claim_ref;
      const ffd::Result<ffd::MutationOutcome> result = runner.registry->revoke_claim(request);
      const std::string context = "revoke " + std::string(ffd::to_string(target.kind));
      Prediction prediction;
      prediction.accept = matches;
      prediction.error = matches ? std::string() : std::string("unknown_fact");
      if (matches) {
        for (const RefClaim& existing : runner.reference.claims) {
          if (existing.kind != FactKind::Retraction || existing.target_kind != target.kind ||
              existing.subject != target.subject || existing.object != target.object ||
              existing.external_authority != target.external_authority ||
              existing.external_resource != target.external_resource ||
              existing.target_authority != target.authority ||
              existing.authority != authority || existing.revision != revision) {
            continue;
          }
          prediction.accept = false;
          prediction.error = "duplicate_claim";
          break;
        }
      }
      finish_op(runner, rng, result, prediction, context, [&] {
                  RefClaim claim;
                  claim.kind = FactKind::Retraction;
                  claim.target_kind = target.kind;
                  claim.subject = target.subject;
                  claim.object = target.object;
                  claim.external = target.external;
                  claim.external_authority = target.external_authority;
                  claim.external_resource = target.external_resource;
                  claim.target_authority = target.authority;
                  claim.authority = authority;
                  claim.revision = revision;
                  runner.reference.claims.push_back(claim);
                });
      continue;
    }

    // Precedence policy.
    const std::uint32_t value = 1 + rng.below(4);
    ffd::SetAuthorityPrecedenceRequest request;
    request.context = ffdtest::make_context("authority.policy", 1, runner.next_key("key"));
    request.authority = ffdtest::authority(authority.c_str());
    request.precedence = value;
    const ffd::Result<ffd::MutationOutcome> result =
        runner.registry->set_authority_precedence(request);
    if (!result.ok()) {
      runner.fail("precedence", "precedence was refused: " + result.error().detail);
    }
    runner.reference.precedence[authority] = value;
    ++runner.accepted;
    verify(runner, rng, "precedence");
  }
}

}  // namespace

FFD_TEST(randomized_state_machine_matches_the_reference_model) {
  for (const std::uint64_t seed : {0x5eed0001ull, 0x5eed0002ull, 0x5eed0003ull}) {
    run_state_machine(seed, 260, false);
  }
}

FFD_TEST(randomized_conflict_and_precedence_machine) {
  for (const std::uint64_t seed : {0xc0ffee01ull, 0xc0ffee02ull}) {
    run_state_machine(seed, 260, true);
  }
}
