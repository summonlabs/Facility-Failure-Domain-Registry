// Facility Failure Domain Registry - DCCP boundary 49.
//
// Read-side algorithms. Every query is a pure function of one immutable
// resolved model; results are ordered by stable identity, never by container or
// thread timing. All traversals are iterative so that deep graphs cannot
// exhaust the stack.
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "canonical.hpp"
#include "ffd/snapshot.hpp"
#include "model.hpp"
#include "validate.hpp"

namespace ffd {
namespace {

using detail::DomainRecord;
using detail::EffectiveEdge;
using detail::ResolvedModel;
using detail::SlotKey;

[[nodiscard]] Error make_error(ErrorCode code, std::string detail) {
  return Error{code, std::move(detail)};
}

struct Graph {
  std::vector<std::vector<std::uint32_t>> out;
  std::vector<std::vector<std::uint32_t>> in;
};

// Exposure graph restricted to edges whose effective precedence is at least
// min_precedence. Precedence 0 keeps every effective edge.
[[nodiscard]] Graph build_graph(const ResolvedModel& model, std::uint32_t min_precedence) {
  Graph graph;
  graph.out.assign(model.domains.size(), {});
  graph.in.assign(model.domains.size(), {});
  for (const EffectiveEdge& edge : model.edges) {
    if (edge.precedence < min_precedence) {
      continue;
    }
    const std::size_t from = model.index_of(edge.from);
    const std::size_t to = model.index_of(edge.to);
    if (from == static_cast<std::size_t>(-1) || to == static_cast<std::size_t>(-1)) {
      continue;
    }
    graph.out[from].push_back(static_cast<std::uint32_t>(to));
    graph.in[to].push_back(static_cast<std::uint32_t>(from));
  }
  for (auto& neighbours : graph.out) {
    std::sort(neighbours.begin(), neighbours.end());
    neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
  }
  for (auto& neighbours : graph.in) {
    std::sort(neighbours.begin(), neighbours.end());
    neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
  }
  return graph;
}

[[nodiscard]] std::vector<std::uint8_t> bfs(
    const std::vector<std::vector<std::uint32_t>>& adjacency, std::uint32_t root,
    std::vector<std::int64_t>* parents = nullptr) {
  std::vector<std::uint8_t> seen(adjacency.size(), 0);
  if (adjacency.empty()) {
    return seen;
  }
  std::vector<std::uint32_t> queue;
  queue.reserve(adjacency.size());
  seen[root] = 1;
  queue.push_back(root);
  std::size_t head = 0;
  while (head < queue.size()) {
    const std::uint32_t node = queue[head];
    ++head;
    for (const std::uint32_t next : adjacency[node]) {
      if (seen[next] != 0) {
        continue;
      }
      seen[next] = 1;
      if (parents != nullptr) {
        (*parents)[next] = static_cast<std::int64_t>(node);
      }
      queue.push_back(next);
    }
  }
  return seen;
}

[[nodiscard]] std::vector<DomainId> collect_ids(const ResolvedModel& model,
                                                const std::vector<std::uint8_t>& seen,
                                                bool include_self, DomainId self) {
  std::vector<DomainId> result;
  for (std::size_t index = 0; index < seen.size(); ++index) {
    if (seen[index] == 0) {
      continue;
    }
    const DomainId id = model.domains[index].id;
    if (!include_self && id == self) {
      continue;
    }
    result.push_back(id);
  }
  std::sort(result.begin(), result.end());
  return result;
}

[[nodiscard]] bool is_same_component(const Graph& graph, std::uint32_t a, std::uint32_t b) {
  if (a == b) {
    return true;
  }
  const std::vector<std::uint8_t> forward = bfs(graph.out, a);
  if (forward[b] == 0) {
    return false;
  }
  const std::vector<std::uint8_t> backward = bfs(graph.out, b);
  return backward[a] != 0;
}

[[nodiscard]] std::vector<DomainId> reconstruct_path(
    const ResolvedModel& model, const std::vector<std::int64_t>& parents, std::uint32_t from,
    std::uint32_t to) {
  std::vector<DomainId> path;
  std::int64_t cursor = static_cast<std::int64_t>(to);
  while (cursor >= 0) {
    path.push_back(model.domains[static_cast<std::size_t>(cursor)].id);
    if (static_cast<std::uint32_t>(cursor) == from) {
      break;
    }
    cursor = parents[static_cast<std::size_t>(cursor)];
  }
  std::reverse(path.begin(), path.end());
  if (path.empty() || !(path.front() == model.domains[from].id)) {
    path.clear();
  }
  return path;
}

[[nodiscard]] std::vector<FactEvidence> effective_evidence(const detail::SlotResolution& slot) {
  std::vector<FactEvidence> evidence;
  for (const FactEvidence& item : slot.evidence) {
    if (item.status == FactStatus::Effective) {
      evidence.push_back(item);
    }
  }
  return evidence;
}

[[nodiscard]] std::string domain_label(const ResolvedModel& model, DomainId id) {
  const DomainRecord* record = model.find_domain(id);
  if (record == nullptr) {
    return "#" + std::to_string(id.value);
  }
  return "#" + std::to_string(id.value) + "(" + record->natural_key + ")";
}

[[nodiscard]] std::string external_label(const ExternalRef& ref) {
  if (ref.empty()) {
    return "-";
  }
  return ref.authority.value + ":" + ref.resource.value;
}

[[nodiscard]] const char* reference_state_name(ReferenceState state) noexcept {
  switch (state) {
    case ReferenceState::Resolved: return "resolved";
    case ReferenceState::NoAlias: return "no_alias";
    case ReferenceState::AmbiguousAlias: return "ambiguous_alias";
    case ReferenceState::InactiveTarget: return "inactive_target";
  }
  return "unknown";
}

[[nodiscard]] std::string slot_label(const SlotKey& key) {
  std::string out = to_string(key.kind);
  out += " ";
  out += std::to_string(key.subject.value);
  out += " ";
  out += std::to_string(key.object.value);
  out += " ";
  out += external_label(key.external);
  return out;
}

// Failure-fate verdict for an ordered pair. Shared fate is proven by mutual
// exposure; independence is only ever a declared claim. The comparison is
// precedence aware: a strictly stronger side wins, an exact tie stays a
// conflict, and the absence of both is unknown rather than independent.
[[nodiscard]] PairVerdictResult compute_pair_verdict(const ResolvedModel& model, DomainId a,
                                                     DomainId b) {
  PairVerdictResult result;
  const std::size_t index_a = model.index_of(a);
  const std::size_t index_b = model.index_of(b);
  if (index_a == static_cast<std::size_t>(-1) || index_b == static_cast<std::size_t>(-1)) {
    return result;
  }

  std::vector<std::uint32_t> thresholds;
  for (const EffectiveEdge& edge : model.edges) {
    thresholds.push_back(edge.precedence);
  }
  std::sort(thresholds.begin(), thresholds.end());
  thresholds.erase(std::unique(thresholds.begin(), thresholds.end()), thresholds.end());

  std::uint32_t strength = 0;
  if (!thresholds.empty()) {
    std::size_t low = 0;
    std::size_t high = thresholds.size();
    std::size_t best = thresholds.size();
    while (low < high) {
      const std::size_t mid = low + (high - low) / 2;
      const Graph graph = build_graph(model, thresholds[mid]);
      if (is_same_component(graph, static_cast<std::uint32_t>(index_a),
                            static_cast<std::uint32_t>(index_b))) {
        best = mid;
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    if (best != thresholds.size()) {
      strength = thresholds[best];
    }
  }
  result.shared_fate_strength = strength;

  std::uint32_t independence_precedence = 0;
  const SlotKey independence_slot =
      detail::canonical_slot(FactKind::Independence, a, b, ExternalRef{});
  const auto independence = model.slots.find(independence_slot);
  if (independence != model.slots.end() && independence->second.asserted) {
    independence_precedence = independence->second.precedence;
    result.independence_evidence = effective_evidence(independence->second);
  }
  result.independence_precedence = independence_precedence;

  if (strength >= 1) {
    const Graph graph = build_graph(model, strength);
    std::vector<std::int64_t> forward_parents(model.domains.size(), -1);
    std::vector<std::int64_t> reverse_parents(model.domains.size(), -1);
    const std::vector<std::uint8_t> forward =
        bfs(graph.out, static_cast<std::uint32_t>(index_a), &forward_parents);
    const std::vector<std::uint8_t> reverse =
        bfs(graph.out, static_cast<std::uint32_t>(index_b), &reverse_parents);
    if (forward[index_b] != 0 && reverse[index_a] != 0) {
      result.witness_forward = reconstruct_path(model, forward_parents,
                                                static_cast<std::uint32_t>(index_a),
                                                static_cast<std::uint32_t>(index_b));
      result.witness_reverse = reconstruct_path(model, reverse_parents,
                                                static_cast<std::uint32_t>(index_b),
                                                static_cast<std::uint32_t>(index_a));
      std::set<SlotKey> witness_slots;
      const auto collect_path_slots = [&](const std::vector<DomainId>& path) {
        for (std::size_t i = 0; i + 1 < path.size(); ++i) {
          for (const EffectiveEdge& edge : model.edges) {
            if (edge.from == path[i] && edge.to == path[i + 1] && edge.precedence >= strength) {
              witness_slots.insert(edge.source);
            }
          }
        }
      };
      collect_path_slots(result.witness_forward);
      collect_path_slots(result.witness_reverse);
      for (const SlotKey& slot : witness_slots) {
        const auto it = model.slots.find(slot);
        if (it == model.slots.end()) {
          continue;
        }
        const std::vector<FactEvidence> evidence = effective_evidence(it->second);
        result.shared_fate_evidence.insert(result.shared_fate_evidence.end(), evidence.begin(),
                                           evidence.end());
      }
      std::sort(result.shared_fate_evidence.begin(), result.shared_fate_evidence.end(),
                [](const FactEvidence& x, const FactEvidence& y) {
                  if (x.kind != y.kind) return x.kind < y.kind;
                  if (x.subject != y.subject) return x.subject < y.subject;
                  if (x.object != y.object) return x.object < y.object;
                  if (x.authority != y.authority) return x.authority < y.authority;
                  return x.authority_revision < y.authority_revision;
                });
    } else {
      result.shared_fate_strength = 0;
      strength = 0;
    }
  }

  if (strength >= 1 && independence_precedence > 0) {
    if (strength > independence_precedence) {
      result.verdict = PairVerdict::ProvenSharedFate;
      result.explanation = "shared-fate proof at precedence " + std::to_string(strength) +
                           " outranks the independence claim at precedence " +
                           std::to_string(independence_precedence);
    } else if (strength == independence_precedence) {
      result.verdict = PairVerdict::Conflicting;
      result.explanation =
          "shared-fate proof and independence claim have equal precedence; the conflict is "
          "preserved";
    } else {
      result.verdict = PairVerdict::ProvenIndependent;
      result.explanation = "independence claim at precedence " +
                           std::to_string(independence_precedence) +
                           " outranks the shared-fate proof at precedence " +
                           std::to_string(strength);
    }
  } else if (strength >= 1) {
    result.verdict = PairVerdict::ProvenSharedFate;
    result.explanation =
        "mutual exposure proves shared fate at precedence " + std::to_string(strength);
  } else if (independence_precedence > 0) {
    result.verdict = PairVerdict::ProvenIndependent;
    result.explanation = "an effective independence claim exists and no shared-fate proof does";
  } else {
    result.verdict = PairVerdict::Unknown;
    result.explanation =
        "no shared-fate proof and no independence claim; unknown is not independence";
  }
  return result;
}

}  // namespace


// ---------------------------------------------------------------------------
// Snapshot lifecycle and metadata
// ---------------------------------------------------------------------------
Snapshot::Snapshot(std::shared_ptr<const detail::SnapshotData> data) : data_(std::move(data)) {}

Snapshot::~Snapshot() = default;

std::uint64_t Snapshot::generation() const noexcept { return data_->model.generation; }

const Digest& Snapshot::digest() const noexcept { return data_->model.digest; }

const Limits& Snapshot::limits() const noexcept { return data_->model.limits; }

ModelBinding Snapshot::binding() const noexcept {
  ModelBinding binding;
  binding.generation = data_->model.generation;
  binding.digest = data_->model.digest;
  return binding;
}

std::size_t Snapshot::domain_count() const noexcept { return data_->model.domains.size(); }

std::size_t Snapshot::fact_count() const noexcept { return data_->model.facts.size(); }

Status Snapshot::verify_binding(const ModelBinding& binding) const {
  if (binding.generation != data_->model.generation) {
    return Status(make_error(ErrorCode::StaleGeneration,
                             "binding expects generation " + std::to_string(binding.generation) +
                                 " but the model is at generation " +
                                 std::to_string(data_->model.generation)));
  }
  if (!(binding.digest == data_->model.digest)) {
    return Status(make_error(ErrorCode::ModelMismatch,
                             "binding digest " + binding.digest.hex() +
                                 " does not match the model digest " +
                                 data_->model.digest.hex()));
  }
  return Status{};
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------
Result<DomainInfo> Snapshot::domain(DomainId id) const {
  const ResolvedModel& model = data_->model;
  const DomainRecord* record = model.find_domain(id);
  if (record == nullptr) {
    return make_error(ErrorCode::UnknownDomain,
                      "domain " + std::to_string(id.value) + " is not in this generation");
  }
  DomainInfo info;
  info.id = record->id;
  info.domain_class = record->domain_class;
  info.natural_key = record->natural_key;
  info.display_name = record->display_name;
  info.lifecycle = model.lifecycle.at(id);
  const auto successor = model.successor.find(id);
  if (successor != model.successor.end()) {
    info.successor = successor->second;
  }
  return info;
}

Result<std::vector<DomainInfo>> Snapshot::domains(bool include_inactive) const {
  const ResolvedModel& model = data_->model;
  std::vector<DomainInfo> result;
  for (const DomainRecord& record : model.domains) {
    const DomainLifecycle lifecycle = model.lifecycle.at(record.id);
    if (!include_inactive && lifecycle != DomainLifecycle::Active) {
      continue;
    }
    DomainInfo info;
    info.id = record.id;
    info.domain_class = record.domain_class;
    info.natural_key = record.natural_key;
    info.display_name = record.display_name;
    info.lifecycle = lifecycle;
    const auto successor = model.successor.find(record.id);
    if (successor != model.successor.end()) {
      info.successor = successor->second;
    }
    result.push_back(std::move(info));
  }
  return result;
}

Result<std::vector<MembershipInfo>> Snapshot::memberships(DomainId id) const {
  const ResolvedModel& model = data_->model;
  if (model.find_domain(id) == nullptr) {
    return make_error(ErrorCode::UnknownDomain, "domain is not in this generation");
  }
  std::vector<MembershipInfo> result;
  for (const auto& [slot, resolution] : model.slots) {
    if (slot.kind != FactKind::Membership || !(slot.subject == id) || !resolution.asserted) {
      continue;
    }
    MembershipInfo info;
    info.domain = id;
    info.resource = slot.external;
    info.evidence = resolution.evidence;
    result.push_back(std::move(info));
  }
  return result;
}

Result<std::vector<DomainId>> Snapshot::containing_domains(const ExternalRef& resource,
                                                           bool include_inactive) const {
  const ResolvedModel& model = data_->model;
  const Status status = detail::validate_external_ref(resource, model.limits);
  if (!status.ok()) {
    return status.error();
  }
  std::vector<DomainId> result;
  const auto it = model.members.find(resource);
  if (it == model.members.end()) {
    return result;
  }
  for (const DomainId id : it->second) {
    if (!include_inactive && !model.is_active(id)) {
      continue;
    }
    result.push_back(id);
  }
  std::sort(result.begin(), result.end());
  return result;
}

Result<std::vector<DomainId>> Snapshot::enclosing_domains(const ExternalRef& resource,
                                                          bool include_inactive) const {
  const ResolvedModel& model = data_->model;
  Result<std::vector<DomainId>> containing = containing_domains(resource, include_inactive);
  if (!containing.ok()) {
    return containing.error();
  }
  // Parents in the containment relation: containment_adjacency is enclosing ->
  // enclosed, so invert it once.
  std::vector<std::vector<std::uint32_t>> parents(model.domains.size());
  for (std::size_t enclosing = 0; enclosing < model.containment_adjacency.size(); ++enclosing) {
    for (const std::uint32_t enclosed : model.containment_adjacency[enclosing]) {
      parents[enclosed].push_back(static_cast<std::uint32_t>(enclosing));
    }
  }
  std::set<DomainId> result;
  std::vector<std::uint32_t> stack;
  std::vector<std::uint8_t> seen(model.domains.size(), 0);
  for (const DomainId start : containing.value()) {
    const std::size_t index = model.index_of(start);
    if (index == static_cast<std::size_t>(-1)) {
      continue;
    }
    result.insert(start);
    if (seen[index] == 0) {
      seen[index] = 1;
      stack.push_back(static_cast<std::uint32_t>(index));
    }
  }
  while (!stack.empty()) {
    const std::uint32_t node = stack.back();
    stack.pop_back();
    for (const std::uint32_t parent : parents[node]) {
      result.insert(model.domains[parent].id);
      if (seen[parent] == 0) {
        seen[parent] = 1;
        stack.push_back(parent);
      }
    }
  }
  return std::vector<DomainId>(result.begin(), result.end());
}

Result<std::vector<DomainId>> Snapshot::domains_for_reference(const ExternalRef& resource) const {
  const ResolvedModel& model = data_->model;
  const Status status = detail::validate_external_ref(resource, model.limits);
  if (!status.ok()) {
    return status.error();
  }
  std::vector<DomainId> result;
  const auto it = model.aliases.find(resource);
  if (it == model.aliases.end()) {
    return result;
  }
  for (const DomainId id : it->second) {
    if (model.is_active(id)) {
      result.push_back(id);
    }
  }
  std::sort(result.begin(), result.end());
  return result;
}

// ---------------------------------------------------------------------------
// Exposure
// ---------------------------------------------------------------------------
Result<std::vector<DomainId>> Snapshot::upstream_exposure(DomainId target,
                                                          ExposureOptions options) const {
  const ResolvedModel& model = data_->model;
  const std::size_t index = model.index_of(target);
  if (index == static_cast<std::size_t>(-1)) {
    return make_error(ErrorCode::UnknownDomain, "target domain is not in this generation");
  }
  if (!model.is_active(target)) {
    return make_error(ErrorCode::DomainNotActive,
                      "target domain is not active in this generation");
  }
  const Graph graph = build_graph(model, 0);
  const std::vector<std::uint8_t> seen =
      bfs(graph.in, static_cast<std::uint32_t>(index));
  return collect_ids(model, seen, options.include_self, target);
}

Result<std::vector<DomainId>> Snapshot::downstream_exposure(DomainId target,
                                                            ExposureOptions options) const {
  const ResolvedModel& model = data_->model;
  const std::size_t index = model.index_of(target);
  if (index == static_cast<std::size_t>(-1)) {
    return make_error(ErrorCode::UnknownDomain, "target domain is not in this generation");
  }
  if (!model.is_active(target)) {
    return make_error(ErrorCode::DomainNotActive,
                      "target domain is not active in this generation");
  }
  const Graph graph = build_graph(model, 0);
  const std::vector<std::uint8_t> seen =
      bfs(graph.out, static_cast<std::uint32_t>(index));
  return collect_ids(model, seen, options.include_self, target);
}

Result<std::vector<DomainId>> Snapshot::common_exposers(const std::vector<DomainId>& targets,
                                                        ExposureOptions options) const {
  const ResolvedModel& model = data_->model;
  if (targets.empty()) {
    return make_error(ErrorCode::InvalidArgument, "at least one target is required");
  }
  const Graph graph = build_graph(model, 0);
  std::vector<std::uint8_t> intersection(model.domains.size(), 1);
  for (const DomainId target : targets) {
    const std::size_t index = model.index_of(target);
    if (index == static_cast<std::size_t>(-1)) {
      return make_error(ErrorCode::UnknownDomain,
                        "target domain " + std::to_string(target.value) +
                            " is not in this generation");
    }
    if (!model.is_active(target)) {
      return make_error(ErrorCode::DomainNotActive,
                        "target domain " + std::to_string(target.value) + " is not active");
    }
    const std::vector<std::uint8_t> seen = bfs(graph.in, static_cast<std::uint32_t>(index));
    for (std::size_t i = 0; i < seen.size(); ++i) {
      if (seen[i] == 0) {
        intersection[i] = 0;
      }
    }
  }
  std::vector<DomainId> result;
  for (std::size_t index = 0; index < intersection.size(); ++index) {
    if (intersection[index] == 0) {
      continue;
    }
    const DomainId id = model.domains[index].id;
    if (!options.include_self &&
        std::find(targets.begin(), targets.end(), id) != targets.end()) {
      continue;
    }
    result.push_back(id);
  }
  std::sort(result.begin(), result.end());
  return result;
}

Result<std::vector<DomainId>> Snapshot::blast_radius(const std::vector<DomainId>& targets,
                                                     ExposureOptions options) const {
  const ResolvedModel& model = data_->model;
  if (targets.empty()) {
    return make_error(ErrorCode::InvalidArgument, "at least one target is required");
  }
  const Graph graph = build_graph(model, 0);
  std::vector<std::uint8_t> seen(model.domains.size(), 0);
  for (const DomainId target : targets) {
    const std::size_t index = model.index_of(target);
    if (index == static_cast<std::size_t>(-1)) {
      return make_error(ErrorCode::UnknownDomain,
                        "target domain " + std::to_string(target.value) +
                            " is not in this generation");
    }
    if (!model.is_active(target)) {
      return make_error(ErrorCode::DomainNotActive,
                        "target domain " + std::to_string(target.value) + " is not active");
    }
    const std::vector<std::uint8_t> reach =
        bfs(graph.out, static_cast<std::uint32_t>(index));
    for (std::size_t i = 0; i < reach.size(); ++i) {
      if (reach[i] != 0) {
        seen[i] = 1;
      }
    }
  }
  std::vector<DomainId> result;
  for (std::size_t index = 0; index < seen.size(); ++index) {
    if (seen[index] == 0) {
      continue;
    }
    const DomainId id = model.domains[index].id;
    if (std::find(targets.begin(), targets.end(), id) != targets.end() && !options.include_self) {
      continue;
    }
    result.push_back(id);
  }
  std::sort(result.begin(), result.end());
  return result;
}

Result<std::vector<ExternalRef>> Snapshot::jointly_exposed_resources(
    const std::vector<ExternalRef>& resources) const {
  const ResolvedModel& model = data_->model;
  if (resources.empty()) {
    return make_error(ErrorCode::InvalidArgument, "at least one resource is required");
  }
  std::set<DomainId> common;
  for (std::size_t i = 0; i < resources.size(); ++i) {
    const Status status = detail::validate_external_ref(resources[i], model.limits);
    if (!status.ok()) {
      return status.error();
    }
    const auto it = model.members.find(resources[i]);
    if (it == model.members.end()) {
      return std::vector<ExternalRef>{};
    }
    std::set<DomainId> current;
    for (const DomainId domain : it->second) {
      if (model.is_active(domain)) {
        current.insert(domain);
      }
    }
    if (current.empty()) {
      return std::vector<ExternalRef>{};
    }
    if (i == 0) {
      common = std::move(current);
    } else {
      std::set<DomainId> intersection;
      std::set_intersection(common.begin(), common.end(), current.begin(), current.end(),
                            std::inserter(intersection, intersection.begin()));
      common = std::move(intersection);
    }
    if (common.empty()) {
      return std::vector<ExternalRef>{};
    }
  }
  std::set<ExternalRef> result;
  for (const DomainId domain : common) {
    for (const auto& [ref, domains] : model.members) {
      if (std::find(domains.begin(), domains.end(), domain) == domains.end()) {
        continue;
      }
      if (std::find(resources.begin(), resources.end(), ref) != resources.end()) {
        continue;
      }
      result.insert(ref);
    }
  }
  return std::vector<ExternalRef>(result.begin(), result.end());
}

// ---------------------------------------------------------------------------
// Failure fate
// ---------------------------------------------------------------------------
Result<std::vector<DomainId>> Snapshot::shared_fate_group(DomainId target) const {
  const ResolvedModel& model = data_->model;
  const std::size_t index = model.index_of(target);
  if (index == static_cast<std::size_t>(-1)) {
    return make_error(ErrorCode::UnknownDomain, "target domain is not in this generation");
  }
  if (!model.is_active(target)) {
    return make_error(ErrorCode::DomainNotActive,
                      "target domain is not active in this generation");
  }
  const std::uint32_t component = model.component[index];
  std::vector<DomainId> result;
  for (std::size_t i = 0; i < model.component.size(); ++i) {
    if (model.component[i] != component || i == index) {
      continue;
    }
    result.push_back(model.domains[i].id);
  }
  std::sort(result.begin(), result.end());
  return result;
}

Result<std::vector<DomainId>> Snapshot::successors(DomainId target) const {
  const ResolvedModel& model = data_->model;
  if (model.find_domain(target) == nullptr) {
    return make_error(ErrorCode::UnknownDomain, "target domain is not in this generation");
  }
  std::vector<DomainId> result;
  const auto it = model.successor.find(target);
  if (it != model.successor.end()) {
    result.push_back(it->second);
  }
  return result;
}

Result<PairVerdictResult> Snapshot::pair_verdict(DomainId a, DomainId b) const {
  const ResolvedModel& model = data_->model;
  if (a == b) {
    return make_error(ErrorCode::InvalidArgument,
                      "a domain cannot be compared with itself");
  }
  const std::size_t index_a = model.index_of(a);
  const std::size_t index_b = model.index_of(b);
  if (index_a == static_cast<std::size_t>(-1) || index_b == static_cast<std::size_t>(-1)) {
    return make_error(ErrorCode::UnknownDomain, "both domains must be in this generation");
  }
  if (!model.is_active(a) || !model.is_active(b)) {
    return make_error(ErrorCode::DomainNotActive, "both domains must be active");
  }

  PairVerdictResult result = compute_pair_verdict(model, a, b);
  return result;
}

Result<std::vector<FactEvidence>> Snapshot::evidence_for(const ClaimRef& claim) const {
  const ResolvedModel& model = data_->model;
  const Status subject_status = detail::validate_domain_id(claim.subject, "claim subject");
  if (!subject_status.ok()) {
    return subject_status.error();
  }
  if (!is_known_fact_kind(static_cast<std::uint16_t>(claim.kind))) {
    return make_error(ErrorCode::InvalidArgument, "claim kind is not known");
  }
  if (claim.kind == FactKind::Retraction) {
    std::vector<FactEvidence> evidence;
    const SlotKey slot =
        detail::canonical_slot(claim.target_kind, claim.subject, claim.object, claim.external);
    for (const auto& [key, resolution] : model.slots) {
      if (!(key == slot)) {
        continue;
      }
      for (const FactEvidence& item : resolution.evidence) {
        if (item.kind == FactKind::Retraction &&
            item.target_authority == claim.target_authority) {
          evidence.push_back(item);
        }
      }
    }
    return evidence;
  }
  const SlotKey slot =
      detail::canonical_slot(claim.kind, claim.subject, claim.object, claim.external);
  const auto it = model.slots.find(slot);
  if (it == model.slots.end()) {
    return std::vector<FactEvidence>{};
  }
  return it->second.evidence;
}

Result<std::vector<ConflictInfo>> Snapshot::conflicts() const {
  const ResolvedModel& model = data_->model;
  std::vector<ConflictInfo> result = model.conflicts;
  // Contradictions that live between claim slots rather than inside one slot:
  // an independence claim that an equally strong shared-fate proof contradicts.
  for (const auto& [slot, resolution] : model.slots) {
    if (slot.kind != FactKind::Independence || !resolution.asserted) {
      continue;
    }
    if (!model.is_active(slot.subject) || !model.is_active(slot.object)) {
      continue;
    }
    const PairVerdictResult verdict = compute_pair_verdict(model, slot.subject, slot.object);
    if (verdict.verdict != PairVerdict::Conflicting) {
      continue;
    }
    ConflictInfo conflict;
    conflict.kind = ConflictKind::Claim;
    conflict.fact_kind = FactKind::Independence;
    conflict.subject = slot.subject;
    conflict.object = slot.object;
    conflict.reason = verdict.explanation;
    conflict.evidence = resolution.evidence;
    conflict.evidence.insert(conflict.evidence.end(), verdict.shared_fate_evidence.begin(),
                             verdict.shared_fate_evidence.end());
    result.push_back(std::move(conflict));
  }
  std::sort(result.begin(), result.end(), [](const ConflictInfo& a, const ConflictInfo& b) {
    if (a.kind != b.kind) return a.kind < b.kind;
    if (a.subject != b.subject) return a.subject < b.subject;
    if (a.object != b.object) return a.object < b.object;
    if (a.external != b.external) return a.external < b.external;
    if (a.fact_kind != b.fact_kind) return a.fact_kind < b.fact_kind;
    return a.target_authority < b.target_authority;
  });
  return result;
}

Result<std::vector<UnresolvedReference>> Snapshot::unresolved_references() const {
  return data_->model.unresolved;
}

// ---------------------------------------------------------------------------
// Deterministic rendering
// ---------------------------------------------------------------------------
std::string Snapshot::canonical_text() const {
  const ResolvedModel& model = data_->model;
  std::string out;
  out += "generation " + std::to_string(model.generation) + "\n";
  out += "digest " + model.digest.hex() + "\n";
  for (const DomainRecord& record : model.domains) {
    out += "domain " + std::to_string(record.id.value) + " " + to_string(record.domain_class) +
           " " + std::string(to_string(model.lifecycle.at(record.id))) + " " + record.natural_key;
    const auto successor = model.successor.find(record.id);
    if (successor != model.successor.end()) {
      out += " successor=" + std::to_string(successor->second.value);
    }
    if (!record.display_name.empty()) {
      out += " name=" + record.display_name;
    }
    out += "\n";
  }
  for (const auto& [slot, resolution] : model.slots) {
    out += "slot " + slot_label(slot) + " ";
    if (resolution.conflicted) {
      out += "conflicting";
    } else if (resolution.asserted) {
      out += "asserted";
    } else if (resolution.retracted) {
      out += "retracted";
    } else {
      out += "absent";
    }
    out += " precedence=" + std::to_string(resolution.precedence) + "\n";
    for (const FactEvidence& evidence : resolution.evidence) {
      out += "  evidence " + std::string(to_string(evidence.kind)) + " " +
             std::string(to_string(evidence.status)) + " authority=" + evidence.authority.value +
             " revision=" + std::to_string(evidence.authority_revision) +
             " precedence=" + std::to_string(evidence.precedence) + "\n";
    }
  }
  for (const EffectiveEdge& edge : model.edges) {
    out += "edge " + domain_label(model, edge.from) + " -> " + domain_label(model, edge.to) +
           " via " + std::string(to_string(edge.source.kind)) +
           " precedence=" + std::to_string(edge.precedence) + "\n";
  }
  for (const ConflictInfo& conflict : model.conflicts) {
    out += "conflict " + std::string(to_string(conflict.kind)) + " " +
           std::string(to_string(conflict.fact_kind)) + " subject=" +
           std::to_string(conflict.subject.value) + " object=" +
           std::to_string(conflict.object.value) + " external=" +
           external_label(conflict.external) + " reason=" + conflict.reason + "\n";
  }
  for (const UnresolvedReference& reference : model.unresolved) {
    out += "unresolved " + std::string(reference_state_name(reference.state)) + " dependent=" +
           std::to_string(reference.dependent.value) + " target=" +
           external_label(reference.target) + "\n";
  }
  return out;
}

}  // namespace ffd
