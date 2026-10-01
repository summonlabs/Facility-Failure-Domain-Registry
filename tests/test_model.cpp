// Facility Failure Domain Registry - model semantics unit tests.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

// Fails the test when the mutation is refused, otherwise yields its outcome.
ffd::MutationOutcome must(ffd::Result<ffd::MutationOutcome> result, const char* what) {
  if (!result.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + " failed: " + result.error().detail);
    throw ::ffdtest::AssertionFailure{what};
  }
  return result.value();
}

void must_fail(const ffd::Result<ffd::MutationOutcome>& result, ffd::ErrorCode expected,
               const char* what) {
  if (result.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + " unexpectedly succeeded");
    return;
  }
  if (result.code() != expected) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + " produced " + ffd::to_string(result.code()) +
                                  " instead of " + ffd::to_string(expected) + ": " +
                                  result.error().detail);
  }
}

struct Fixture {
  ffdtest::ScratchDir scratch{"model"};
  std::unique_ptr<ffd::Registry> registry;
  std::uint64_t counter{0};

  explicit Fixture(ffd::Durability durability = ffd::Durability::ExplicitPublish) {
    ffd::StoreConfig config;
    config.path = scratch.file("store.ffdr");
    config.durability = durability;
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::move(opened.value());
  }

  [[nodiscard]] ffd::MutationContext context(const char* who = "authority.alpha",
                                             std::uint64_t revision = 1) {
    return ffdtest::make_context(who, revision, ffdtest::index_key("op", ++counter));
  }

  [[nodiscard]] ffd::DomainId create(const std::string& key,
                                     ffd::DomainClass domain_class = ffd::DomainClass::Rack,
                                     const char* who = "authority.alpha") {
    ffd::CreateDomainRequest request;
    request.context = context(who);
    request.domain_class = domain_class;
    request.natural_key = key;
    return must(registry->create_domain(request), "create_domain").domain;
  }

  void membership(ffd::DomainId domain, const ffd::ExternalRef& resource,
                  const char* who = "authority.alpha", std::uint64_t revision = 1) {
    ffd::AddMembershipRequest request;
    request.context = context(who, revision);
    request.domain = domain;
    request.resource = resource;
    must(registry->add_membership(request), "add_membership");
  }

  void containment(ffd::DomainId parent, ffd::DomainId child,
                   const char* who = "authority.alpha", std::uint64_t revision = 1) {
    ffd::DeclareContainmentRequest request;
    request.context = context(who, revision);
    request.parent = parent;
    request.child = child;
    must(registry->declare_containment(request), "declare_containment");
  }

  void shared_fate(ffd::DomainId a, ffd::DomainId b, const char* who = "authority.alpha",
                   std::uint64_t revision = 1) {
    ffd::DeclareSharedFateRequest request;
    request.context = context(who, revision);
    request.a = a;
    request.b = b;
    must(registry->declare_shared_fate(request), "declare_shared_fate");
  }

  void independence(ffd::DomainId a, ffd::DomainId b, const char* who = "authority.alpha",
                    std::uint64_t revision = 1) {
    ffd::DeclareIndependenceRequest request;
    request.context = context(who, revision);
    request.a = a;
    request.b = b;
    must(registry->declare_independence(request), "declare_independence");
  }

  void dependency(ffd::DomainId dependent, ffd::DomainId target,
                  const char* who = "authority.alpha", std::uint64_t revision = 1) {
    ffd::DeclareDependencyRequest request;
    request.context = context(who, revision);
    request.dependent = dependent;
    request.target = target;
    must(registry->declare_dependency(request), "declare_dependency");
  }

  void precedence(const char* who, std::uint32_t value, const char* actor = "authority.policy") {
    ffd::SetAuthorityPrecedenceRequest request;
    request.context = context(actor);
    request.authority = ffdtest::authority(who);
    request.precedence = value;
    must(registry->set_authority_precedence(request), "set_authority_precedence");
  }

  [[nodiscard]] std::vector<ffd::DomainId> ids(const ffd::Result<std::vector<ffd::DomainId>>& r) {
    FFD_REQUIRE(r.ok());
    return r.value();
  }
};

[[nodiscard]] bool has(const std::vector<ffd::DomainId>& values, ffd::DomainId id) {
  return std::find(values.begin(), values.end(), id) != values.end();
}

}  // namespace

FFD_TEST(domain_creation_and_identity) {
  Fixture fixture;
  const ffd::DomainId first = fixture.create("room-a", ffd::DomainClass::Room);
  const ffd::DomainId second = fixture.create("room-b", ffd::DomainClass::Room);
  FFD_CHECK_EQ(first.value, 1u);
  FFD_CHECK_EQ(second.value, 2u);

  // Duplicate natural key inside one class is refused; a different class is a
  // different namespace of facts.
  {
    ffd::CreateDomainRequest request;
    request.context = fixture.context();
    request.domain_class = ffd::DomainClass::Room;
    request.natural_key = "room-a";
    must_fail(fixture.registry->create_domain(request), ffd::ErrorCode::DuplicateNaturalKey,
              "duplicate natural key");
  }
  {
    ffd::CreateDomainRequest request;
    request.context = fixture.context();
    request.domain_class = ffd::DomainClass::Rack;
    request.natural_key = "room-a";
    must( fixture.registry->create_domain(request), "same key different class");
  }

  // Identity reuse is refused, including an identity below the high-water mark
  // that was never materialised.
  {
    ffd::CreateDomainRequest request;
    request.context = fixture.context();
    request.domain_class = ffd::DomainClass::Row;
    request.natural_key = "row-x";
    request.requested_id = ffd::DomainId{1};
    must_fail(fixture.registry->create_domain(request), ffd::ErrorCode::DuplicateIdentity,
              "identity reuse");
  }
  {
    ffd::CreateDomainRequest request;
    request.context = fixture.context();
    request.domain_class = ffd::DomainClass::Row;
    request.natural_key = "row-y";
    request.requested_id = ffd::DomainId{1000};
    const ffd::MutationOutcome outcome =
        must(fixture.registry->create_domain(request), "explicit identity");
    FFD_CHECK_EQ(outcome.domain.value, 1000u);
  }
  {
    ffd::CreateDomainRequest request;
    request.context = fixture.context();
    request.domain_class = ffd::DomainClass::Row;
    request.natural_key = "row-z";
    const ffd::MutationOutcome outcome =
        must(fixture.registry->create_domain(request), "identity after explicit");
    FFD_CHECK_EQ(outcome.domain.value, 1001u);
  }

  // Every mutation needs an idempotency key unless the store opts out.
  {
    ffd::CreateDomainRequest request;
    request.context = ffdtest::make_context_without_key("authority.alpha", 1);
    request.domain_class = ffd::DomainClass::Row;
    request.natural_key = "row-keyless";
    must_fail(fixture.registry->create_domain(request), ffd::ErrorCode::IdempotencyKeyRequired,
              "keyless mutation");
  }

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK_EQ(snapshot.domain_count(), std::size_t{5});
  const ffd::Result<ffd::DomainInfo> info = snapshot.domain(first);
  FFD_REQUIRE(info.ok());
  FFD_CHECK_EQ(std::string(info.value().natural_key), std::string("room-a"));
  FFD_CHECK(info.value().lifecycle == ffd::DomainLifecycle::Active);
  FFD_CHECK_EQ(snapshot.domain(ffd::DomainId{9999}).code(), ffd::ErrorCode::UnknownDomain);
}

FFD_TEST(membership_is_an_explicit_declaration) {
  Fixture fixture;
  const ffd::DomainId room = fixture.create("room-a", ffd::DomainClass::Room);
  const ffd::DomainId rack_one = fixture.create("rack-1", ffd::DomainClass::Rack);
  const ffd::DomainId rack_two = fixture.create("rack-2", ffd::DomainClass::Rack);
  const ffd::ExternalRef asset = ffdtest::external("asset.registry", "asset-17");

  fixture.membership(rack_one, asset);

  ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(has(fixture.ids(snapshot.containing_domains(asset)), rack_one));
  FFD_CHECK(!has(fixture.ids(snapshot.containing_domains(asset)), rack_two));
  FFD_CHECK(!has(fixture.ids(snapshot.containing_domains(asset)), room));

  // Repeating an identical claim from the same authority at the same revision is
  // a duplicate, not corroboration.
  {
    ffd::AddMembershipRequest request;
    request.context = ffdtest::make_context("authority.alpha", 1, "repeat-key");
    request.domain = rack_one;
    request.resource = asset;
    must_fail(fixture.registry->add_membership(request), ffd::ErrorCode::DuplicateClaim,
              "duplicate membership claim");
  }

  // A different authority corroborates the same membership.
  fixture.membership(rack_one, asset, "authority.beta", 4);
  snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<ffd::MembershipInfo>> memberships =
      snapshot.memberships(rack_one);
  FFD_REQUIRE(memberships.ok());
  FFD_REQUIRE(memberships.value().size() == 1);
  FFD_CHECK_EQ(memberships.value().front().evidence.size(), std::size_t{2});

  // Proximity and shared rows are not shared fate.
  FFD_CHECK_EQ(std::string(ffd::to_string(
                   snapshot.pair_verdict(rack_one, rack_two).value().verdict)),
               std::string("unknown"));

  // Invalid or unknown inputs are refused.
  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.domain = rack_one;
    request.resource = ffdtest::external("asset.registry", "");
    must_fail(fixture.registry->add_membership(request), ffd::ErrorCode::InvalidArgument,
              "empty resource id");
  }
  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.domain = ffd::DomainId{4242};
    request.resource = asset;
    must_fail(fixture.registry->add_membership(request), ffd::ErrorCode::UnknownDomain,
              "unknown domain");
  }
}

FFD_TEST(containment_is_distinct_from_membership) {
  Fixture fixture;
  const ffd::DomainId room = fixture.create("room-a", ffd::DomainClass::Room);
  const ffd::DomainId row = fixture.create("row-1", ffd::DomainClass::Row);
  const ffd::DomainId rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  const ffd::ExternalRef asset = ffdtest::external("asset.registry", "asset-17");

  fixture.containment(room, row);
  fixture.containment(row, rack);
  fixture.membership(rack, asset);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const std::vector<ffd::DomainId> containing = fixture.ids(snapshot.containing_domains(asset));
  FFD_REQUIRE(containing.size() == 1);
  FFD_CHECK(containing.front() == rack);
  const std::vector<ffd::DomainId> enclosing = fixture.ids(snapshot.enclosing_domains(asset));
  FFD_REQUIRE(enclosing.size() == 3);
  FFD_CHECK(has(enclosing, rack));
  FFD_CHECK(has(enclosing, row));
  FFD_CHECK(has(enclosing, room));

  // A room failure exposes everything nested in it.
  const std::vector<ffd::DomainId> downstream = fixture.ids(snapshot.downstream_exposure(room));
  FFD_CHECK(has(downstream, row));
  FFD_CHECK(has(downstream, rack));
  // A rack failure does not fail the room.
  const std::vector<ffd::DomainId> rack_downstream = fixture.ids(snapshot.downstream_exposure(rack));
  FFD_CHECK(rack_downstream.empty());
  const std::vector<ffd::DomainId> rack_upstream = fixture.ids(snapshot.upstream_exposure(rack));
  FFD_CHECK(has(rack_upstream, row));
  FFD_CHECK(has(rack_upstream, room));

  // Nesting alone never proves shared fate.
  FFD_CHECK(snapshot.pair_verdict(room, rack).value().verdict == ffd::PairVerdict::Unknown);
}

FFD_TEST(containment_cycles_are_refused) {
  Fixture fixture;
  const ffd::DomainId a = fixture.create("a");
  const ffd::DomainId b = fixture.create("b");
  const ffd::DomainId c = fixture.create("c");
  fixture.containment(a, b);
  fixture.containment(b, c);
  {
    ffd::DeclareContainmentRequest request;
    request.context = fixture.context();
    request.parent = c;
    request.child = a;
    must_fail(fixture.registry->declare_containment(request), ffd::ErrorCode::CycleNotAllowed,
              "containment cycle");
  }
  {
    ffd::DeclareContainmentRequest request;
    request.context = fixture.context();
    request.parent = a;
    request.child = a;
    must_fail(fixture.registry->declare_containment(request), ffd::ErrorCode::SelfReference,
              "self containment");
  }
  // The refused declarations left no trace.
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(fixture.ids(snapshot.downstream_exposure(a)).size() == 2);
  FFD_CHECK_EQ(snapshot.fact_count(), std::size_t{2});
}

FFD_TEST(shared_fate_is_transitive_and_independence_is_not) {
  Fixture fixture;
  const ffd::DomainId a = fixture.create("a", ffd::DomainClass::PowerDistribution);
  const ffd::DomainId b = fixture.create("b", ffd::DomainClass::PowerDistribution);
  const ffd::DomainId c = fixture.create("c", ffd::DomainClass::PowerDistribution);
  fixture.shared_fate(a, b);
  fixture.shared_fate(b, c);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(snapshot.pair_verdict(a, b).value().verdict == ffd::PairVerdict::ProvenSharedFate);
  FFD_CHECK(snapshot.pair_verdict(a, c).value().verdict == ffd::PairVerdict::ProvenSharedFate);
  const std::vector<ffd::DomainId> group = fixture.ids(snapshot.shared_fate_group(a));
  FFD_REQUIRE(group.size() == 2);
  FFD_CHECK(has(group, b));
  FFD_CHECK(has(group, c));
  const ffd::PairVerdictResult verdict = snapshot.pair_verdict(a, c).value();
  FFD_CHECK(!verdict.witness_forward.empty());
  FFD_CHECK(!verdict.witness_reverse.empty());
  FFD_CHECK(!verdict.shared_fate_evidence.empty());
}

FFD_TEST(mutual_dependency_proves_shared_fate) {
  Fixture fixture;
  const ffd::DomainId a = fixture.create("a", ffd::DomainClass::SharedService);
  const ffd::DomainId b = fixture.create("b", ffd::DomainClass::SharedService);
  fixture.dependency(a, b);
  // A one-way dependency is exposure, not shared fate.
  FFD_CHECK(fixture.registry->snapshot().pair_verdict(a, b).value().verdict ==
            ffd::PairVerdict::Unknown);
  fixture.dependency(b, a);
  FFD_CHECK(fixture.registry->snapshot().pair_verdict(a, b).value().verdict ==
            ffd::PairVerdict::ProvenSharedFate);
}

FFD_TEST(independence_versus_shared_fate_conflicts) {
  Fixture fixture;
  const ffd::DomainId a = fixture.create("a");
  const ffd::DomainId b = fixture.create("b");

  // Unknown independence is not independence.
  FFD_CHECK(fixture.registry->snapshot().pair_verdict(a, b).value().verdict ==
            ffd::PairVerdict::Unknown);

  fixture.independence(a, b);
  FFD_CHECK(fixture.registry->snapshot().pair_verdict(a, b).value().verdict ==
            ffd::PairVerdict::ProvenIndependent);

  // An equal-precedence shared-fate declaration contradicts the independence
  // claim; the model preserves the conflict instead of choosing.
  fixture.shared_fate(a, b);
  ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(snapshot.pair_verdict(a, b).value().verdict == ffd::PairVerdict::Conflicting);
  const std::vector<ffd::ConflictInfo> independence_conflicts = snapshot.conflicts().value();
  FFD_REQUIRE(independence_conflicts.size() == 1);
  FFD_CHECK_EQ(std::string(ffd::to_string(independence_conflicts.front().kind)),
               std::string("claim"));
  FFD_CHECK(independence_conflicts.front().fact_kind == ffd::FactKind::Independence);

  // Explicit precedence resolves it deterministically.
  fixture.precedence("authority.alpha", 7);
  snapshot = fixture.registry->snapshot();
  FFD_CHECK(snapshot.pair_verdict(a, b).value().verdict == ffd::PairVerdict::Conflicting);

  ffd::DeclareIndependenceRequest stronger;
  stronger.context = ffdtest::make_context("authority.strong", 1, "strong-independence");
  stronger.a = a;
  stronger.b = b;
  must(fixture.registry->declare_independence(stronger), "strong independence");
  fixture.precedence("authority.strong", 9);
  snapshot = fixture.registry->snapshot();
  const ffd::PairVerdictResult verdict = snapshot.pair_verdict(a, b).value();
  FFD_CHECK(verdict.verdict == ffd::PairVerdict::ProvenIndependent);
  FFD_CHECK_EQ(verdict.independence_precedence, 9u);
  FFD_CHECK_EQ(verdict.shared_fate_strength, 7u);
}

FFD_TEST(retirement_and_supersession) {
  Fixture fixture;
  const ffd::DomainId old_rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  const ffd::DomainId neighbor = fixture.create("rack-2", ffd::DomainClass::Rack);
  fixture.shared_fate(old_rack, neighbor);
  const ffd::ExternalRef asset = ffdtest::external("asset.registry", "asset-1");
  fixture.membership(old_rack, asset);

  {
    ffd::RetireDomainRequest request;
    request.context = fixture.context();
    request.domain = old_rack;
    request.reason = "decommissioned";
    must(fixture.registry->retire_domain(request), "retire");
  }
  {
    ffd::RetireDomainRequest request;
    request.context = fixture.context();
    request.domain = old_rack;
    must_fail(fixture.registry->retire_domain(request), ffd::ErrorCode::AlreadyRetired,
              "double retirement");
  }
  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.domain = old_rack;
    request.resource = ffdtest::external("asset.registry", "asset-2");
    must_fail(fixture.registry->add_membership(request), ffd::ErrorCode::DomainNotActive,
              "membership on retired domain");
  }

  const ffd::Snapshot retired_view = fixture.registry->snapshot();
  FFD_CHECK(retired_view.domain(old_rack).value().lifecycle == ffd::DomainLifecycle::Retired);
  // Retired domains are historical: they leave the current exposure model.
  FFD_CHECK(retired_view.pair_verdict(old_rack, neighbor).code() == ffd::ErrorCode::DomainNotActive);
  FFD_CHECK(retired_view.downstream_exposure(old_rack).code() == ffd::ErrorCode::DomainNotActive);
  FFD_CHECK(fixture.ids(retired_view.containing_domains(asset)).empty());
  FFD_CHECK(fixture.ids(retired_view.containing_domains(asset, true)).size() == 1);
  FFD_CHECK(retired_view.domains(false).value().size() == 1);
  FFD_CHECK(retired_view.domains(true).value().size() == 2);

  // Replacement is explicit and linked, not inferred.
  ffd::SupersedeDomainRequest supersede;
  supersede.context = fixture.context();
  supersede.predecessor = old_rack;
  supersede.domain_class = ffd::DomainClass::Rack;
  supersede.natural_key = "rack-1-replacement";
  const ffd::MutationOutcome outcome =
      must(fixture.registry->supersede_domain(supersede), "supersede");
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::DomainInfo predecessor = snapshot.domain(old_rack).value();
  FFD_CHECK(predecessor.lifecycle == ffd::DomainLifecycle::Superseded);
  FFD_CHECK(predecessor.successor == outcome.domain);
  const std::vector<ffd::DomainId> successors = fixture.ids(snapshot.successors(old_rack));
  FFD_REQUIRE(successors.size() == 1);
  FFD_CHECK(successors.front() == outcome.domain);
  // The successor starts with no inherited relationships.
  FFD_CHECK(snapshot.pair_verdict(outcome.domain, neighbor).value().verdict ==
            ffd::PairVerdict::Unknown);
}

FFD_TEST(competing_successors_stay_a_conflict) {
  Fixture fixture;
  const ffd::DomainId old_rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  ffd::SupersedeDomainRequest first;
  first.context = fixture.context();
  first.predecessor = old_rack;
  first.natural_key = "rack-1-a";
  must(fixture.registry->supersede_domain(first), "first successor");
  ffd::SupersedeDomainRequest second;
  second.context = fixture.context("authority.beta");
  second.predecessor = old_rack;
  second.natural_key = "rack-1-b";
  must(fixture.registry->supersede_domain(second), "second successor");

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(snapshot.domain(old_rack).value().lifecycle != ffd::DomainLifecycle::Superseded);
  const std::vector<ffd::ConflictInfo> conflicts = snapshot.conflicts().value();
  bool found_supersession_conflict = false;
  for (const ffd::ConflictInfo& conflict : conflicts) {
    if (conflict.kind == ffd::ConflictKind::Supersession) {
      found_supersession_conflict = true;
    }
  }
  FFD_CHECK(found_supersession_conflict);
  FFD_CHECK(fixture.ids(snapshot.successors(old_rack)).empty());
}

FFD_TEST(external_references_resolve_only_through_aliases) {
  Fixture fixture;
  const ffd::DomainId dependent = fixture.create("service-a", ffd::DomainClass::SharedService);
  const ffd::DomainId upstream = fixture.create("ups-a", ffd::DomainClass::PowerSource);
  const ffd::ExternalRef external_ups = ffdtest::external("dccp.topology", "ups-9");

  {
    ffd::DeclareDependencyRequest request;
    request.context = fixture.context();
    request.dependent = dependent;
    request.external_target = external_ups;
    must(fixture.registry->declare_dependency(request), "external dependency");
  }
  ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_REQUIRE(snapshot.unresolved_references().value().size() == 1);
  FFD_CHECK(snapshot.unresolved_references().value().front().state ==
            ffd::ReferenceState::NoAlias);
  FFD_CHECK(fixture.ids(snapshot.upstream_exposure(dependent)).empty());

  {
    ffd::DeclareAliasRequest request;
    request.context = fixture.context();
    request.domain = upstream;
    request.resource = external_ups;
    must(fixture.registry->declare_alias(request), "alias");
  }
  snapshot = fixture.registry->snapshot();
  FFD_CHECK(snapshot.unresolved_references().value().empty());
  FFD_CHECK(has(fixture.ids(snapshot.upstream_exposure(dependent)), upstream));
  FFD_CHECK(fixture.ids(snapshot.domains_for_reference(external_ups)).size() == 1);

  // A second domain claiming the same external identity is ambiguous, not a
  // silent pick.
  const ffd::DomainId second_upstream = fixture.create("ups-b", ffd::DomainClass::PowerSource);
  {
    ffd::DeclareAliasRequest request;
    request.context = fixture.context();
    request.domain = second_upstream;
    request.resource = external_ups;
    must(fixture.registry->declare_alias(request), "second alias");
  }
  snapshot = fixture.registry->snapshot();
  FFD_REQUIRE(snapshot.unresolved_references().value().size() == 1);
  FFD_CHECK(snapshot.unresolved_references().value().front().state ==
            ffd::ReferenceState::AmbiguousAlias);
  FFD_CHECK(fixture.ids(snapshot.upstream_exposure(dependent)).empty());
  const std::vector<ffd::ConflictInfo> alias_conflicts = snapshot.conflicts().value();
  bool ambiguous_conflict = false;
  for (const ffd::ConflictInfo& conflict : alias_conflicts) {
    if (conflict.kind == ffd::ConflictKind::AmbiguousAlias) {
      ambiguous_conflict = true;
    }
  }
  FFD_CHECK(ambiguous_conflict);
}

FFD_TEST(retraction_respects_precedence) {
  Fixture fixture;
  const ffd::DomainId rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  const ffd::ExternalRef asset = ffdtest::external("asset.registry", "asset-1");
  fixture.precedence("authority.alpha", 5);
  fixture.precedence("authority.weak", 1);
  fixture.precedence("authority.beta", 5);
  fixture.membership(rack, asset, "authority.alpha");

  ffd::ClaimRef claim;
  claim.kind = ffd::FactKind::Membership;
  claim.subject = rack;
  claim.external = asset;
  claim.target_authority = ffdtest::authority("authority.alpha");

  // A lower-precedence retraction does not displace the claim.
  {
    ffd::RevokeClaimRequest request;
    request.context = fixture.context("authority.weak");
    request.claim = claim;
    must(fixture.registry->revoke_claim(request), "weak retraction");
  }
  ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK(fixture.ids(snapshot.containing_domains(asset)).size() == 1);

  // An equal-precedence retraction contradicts the claim.
  {
    ffd::RevokeClaimRequest request;
    request.context = fixture.context("authority.beta");
    request.claim = claim;
    must(fixture.registry->revoke_claim(request), "equal retraction");
  }
  snapshot = fixture.registry->snapshot();
  FFD_CHECK(fixture.ids(snapshot.containing_domains(asset)).empty());
  const std::vector<ffd::ConflictInfo> claim_conflicts = snapshot.conflicts().value();
  FFD_CHECK(!claim_conflicts.empty());

  // Precedence resolves it: the retracting authority outranks the claimant.
  fixture.precedence("authority.beta", 7);
  snapshot = fixture.registry->snapshot();
  FFD_CHECK(fixture.ids(snapshot.containing_domains(asset)).empty());
  const std::vector<ffd::ConflictInfo> resolved_conflicts = snapshot.conflicts().value();
  bool claim_conflict = false;
  for (const ffd::ConflictInfo& conflict : resolved_conflicts) {
    if (conflict.kind == ffd::ConflictKind::Claim) {
      claim_conflict = true;
    }
  }
  FFD_CHECK(!claim_conflict);
  // The retracted claim is preserved as evidence, never erased.
  const ffd::Result<std::vector<ffd::FactEvidence>> evidence = snapshot.evidence_for(claim);
  FFD_REQUIRE(evidence.ok());
  FFD_CHECK(!evidence.value().empty());
}

FFD_TEST(retraction_of_absent_claim_is_refused) {
  Fixture fixture;
  const ffd::DomainId rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  ffd::ClaimRef claim;
  claim.kind = ffd::FactKind::Membership;
  claim.subject = rack;
  claim.external = ffdtest::external("asset.registry", "never-declared");
  claim.target_authority = ffdtest::authority("authority.alpha");
  ffd::RevokeClaimRequest request;
  request.context = fixture.context();
  request.claim = claim;
  must_fail(fixture.registry->revoke_claim(request), ffd::ErrorCode::UnknownFact,
            "retraction of an absent claim");
}

FFD_TEST(generation_preconditions_and_bindings) {
  Fixture fixture(ffd::Durability::DurablePerMutation);
  const ffd::DomainId rack = fixture.create("rack-1", ffd::DomainClass::Rack);
  FFD_CHECK_EQ(fixture.registry->generation(), 1u);
  const ffd::ModelBinding binding = fixture.registry->snapshot().binding();
  FFD_CHECK(fixture.registry->snapshot().verify_binding(binding).ok());

  // A tampered digest at the current generation is a content mismatch, not
  // staleness.
  ffd::ModelBinding mismatched = binding;
  mismatched.digest = ffd::Digest{};
  FFD_CHECK_EQ(fixture.registry->snapshot().verify_binding(mismatched).code(),
               ffd::ErrorCode::ModelMismatch);

  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.context.expected_generation = 0;
    request.domain = rack;
    request.resource = ffdtest::external("asset.registry", "asset-1");
    must(fixture.registry->add_membership(request), "unconditional mutation");
  }

  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.context.expected_generation = 1;
    request.domain = rack;
    request.resource = ffdtest::external("asset.registry", "asset-2");
    must_fail(fixture.registry->add_membership(request), ffd::ErrorCode::StaleGeneration,
              "stale precondition");
  }
  {
    ffd::AddMembershipRequest request;
    request.context = fixture.context();
    request.context.expected_generation = 2;
    request.domain = rack;
    request.resource = ffdtest::external("asset.registry", "asset-2");
    must(fixture.registry->add_membership(request), "fresh precondition");
  }

  FFD_CHECK_EQ(fixture.registry->snapshot().verify_binding(binding).code(),
               ffd::ErrorCode::StaleGeneration);
}

FFD_TEST(deep_and_wide_graphs_stay_iterative) {
  Fixture fixture;
  constexpr std::uint32_t kDepth = 2000;
  std::vector<ffd::DomainId> chain;
  chain.reserve(kDepth);
  for (std::uint32_t i = 0; i < kDepth; ++i) {
    chain.push_back(fixture.create("chain-" + std::to_string(i), ffd::DomainClass::Row));
  }
  for (std::uint32_t i = 1; i < kDepth; ++i) {
    fixture.containment(chain[i - 1], chain[i]);
  }
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const std::vector<ffd::DomainId> downstream =
      fixture.ids(snapshot.downstream_exposure(chain.front()));
  FFD_CHECK_EQ(downstream.size(), std::size_t{kDepth - 1});
  FFD_CHECK_EQ(fixture.ids(snapshot.upstream_exposure(chain.back())).size(),
               std::size_t{kDepth - 1});
  FFD_CHECK_EQ(fixture.ids(snapshot.shared_fate_group(chain.front())).size(), std::size_t{0});
}
