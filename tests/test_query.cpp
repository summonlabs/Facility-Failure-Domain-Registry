// Facility Failure Domain Registry - query semantics tests.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;

struct Fixture {
  ffdtest::ScratchDir scratch{"query"};
  std::unique_ptr<ffd::Registry> registry;
  std::uint64_t counter{0};

  Fixture() {
    ffd::StoreConfig config;
    config.path = scratch.file("store.ffdr");
    config.durability = ffd::Durability::ExplicitPublish;
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::move(opened.value());
  }

  [[nodiscard]] ffd::MutationContext context(const char* who = "authority.alpha",
                                             std::uint64_t revision = 1) {
    return ffdtest::make_context(who, revision, ffdtest::index_key("q", ++counter));
  }

  [[nodiscard]] DomainId create(const std::string& key,
                                ffd::DomainClass domain_class = ffd::DomainClass::Rack) {
    ffd::CreateDomainRequest request;
    request.context = context();
    request.domain_class = domain_class;
    request.natural_key = key;
    ffd::Result<ffd::MutationOutcome> outcome = registry->create_domain(request);
    if (!outcome.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "create failed: " + outcome.error().detail);
      throw ::ffdtest::AssertionFailure{"create"};
    }
    return outcome.value().domain;
  }

  void membership(DomainId domain, const ffd::ExternalRef& resource) {
    ffd::AddMembershipRequest request;
    request.context = context();
    request.domain = domain;
    request.resource = resource;
    FFD_REQUIRE(registry->add_membership(request).ok());
  }

  void containment(DomainId parent, DomainId child) {
    ffd::DeclareContainmentRequest request;
    request.context = context();
    request.parent = parent;
    request.child = child;
    FFD_REQUIRE(registry->declare_containment(request).ok());
  }

  void dependency(DomainId dependent, DomainId target) {
    ffd::DeclareDependencyRequest request;
    request.context = context();
    request.dependent = dependent;
    request.target = target;
    FFD_REQUIRE(registry->declare_dependency(request).ok());
  }

  void shared_fate(DomainId a, DomainId b) {
    ffd::DeclareSharedFateRequest request;
    request.context = context();
    request.a = a;
    request.b = b;
    FFD_REQUIRE(registry->declare_shared_fate(request).ok());
  }
};

[[nodiscard]] bool has(const std::vector<DomainId>& values, DomainId id) {
  return std::find(values.begin(), values.end(), id) != values.end();
}

[[nodiscard]] std::string strip_generation(const std::string& text) {
  const std::size_t newline = text.find('\n');
  return newline == std::string::npos ? text : text.substr(newline + 1);
}

}  // namespace

FFD_TEST(common_exposers_and_blast_radius) {
  Fixture fixture;
  const DomainId pdu = fixture.create("pdu-1", ffd::DomainClass::PowerDistribution);
  const DomainId room = fixture.create("room-a", ffd::DomainClass::Room);
  const DomainId rack_a = fixture.create("rack-a", ffd::DomainClass::Rack);
  const DomainId rack_b = fixture.create("rack-b", ffd::DomainClass::Rack);
  fixture.dependency(rack_a, pdu);
  fixture.dependency(rack_b, pdu);
  fixture.containment(room, rack_a);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const std::vector<DomainId> targets{rack_a, rack_b};

  const ffd::Result<std::vector<DomainId>> together = snapshot.common_exposers(targets);
  FFD_REQUIRE(together.ok());
  FFD_CHECK(has(together.value(), pdu));
  FFD_CHECK(!has(together.value(), room));
  FFD_CHECK(!has(together.value(), rack_a));

  // The PDU is the only domain that exposes both the PDU and rack-a, so it is a
  // single point of failure for that pair. A target is only reported when the
  // caller opts in.
  const ffd::Result<std::vector<DomainId>> pair =
      snapshot.common_exposers({pdu, rack_a});
  FFD_REQUIRE(pair.ok());
  FFD_CHECK(pair.value().empty());
  const ffd::Result<std::vector<DomainId>> with_self =
      snapshot.common_exposers({pdu, rack_a}, ffd::ExposureOptions{true});
  FFD_REQUIRE(with_self.ok());
  FFD_CHECK_EQ(with_self.value().size(), std::size_t{1});
  FFD_CHECK(has(with_self.value(), pdu));

  const ffd::Result<std::vector<DomainId>> radius = snapshot.blast_radius({pdu});
  FFD_REQUIRE(radius.ok());
  FFD_CHECK(has(radius.value(), rack_a));
  FFD_CHECK(has(radius.value(), rack_b));
  FFD_CHECK(!has(radius.value(), pdu));
  FFD_CHECK(!has(radius.value(), room));

  const ffd::Result<std::vector<DomainId>> radius_with_self =
      snapshot.blast_radius({pdu}, ffd::ExposureOptions{true});
  FFD_REQUIRE(radius_with_self.ok());
  FFD_CHECK(has(radius_with_self.value(), pdu));

  FFD_CHECK_EQ(snapshot.common_exposers({}).code(), ffd::ErrorCode::InvalidArgument);
  FFD_CHECK_EQ(snapshot.blast_radius({DomainId{4242}}).code(), ffd::ErrorCode::UnknownDomain);
}

FFD_TEST(dependency_chains_expose_upstream_and_downstream) {
  Fixture fixture;
  const DomainId a = fixture.create("a", ffd::DomainClass::SharedService);
  const DomainId b = fixture.create("b", ffd::DomainClass::SharedService);
  const DomainId c = fixture.create("c", ffd::DomainClass::SharedService);
  const DomainId d = fixture.create("d", ffd::DomainClass::SharedService);
  fixture.dependency(b, a);  // b depends on a
  fixture.dependency(c, b);
  fixture.dependency(d, c);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  // a is fed by nothing; d is fed by the whole chain.
  const ffd::Result<std::vector<DomainId>> upstream_of_a = snapshot.upstream_exposure(a);
  FFD_REQUIRE(upstream_of_a.ok());
  FFD_CHECK(upstream_of_a.value().empty());

  const ffd::Result<std::vector<DomainId>> upstream_of_d = snapshot.upstream_exposure(d);
  FFD_REQUIRE(upstream_of_d.ok());
  FFD_CHECK_EQ(upstream_of_d.value().size(), std::size_t{3});
  FFD_CHECK(has(upstream_of_d.value(), a));

  const ffd::Result<std::vector<DomainId>> downstream_of_a = snapshot.downstream_exposure(a);
  FFD_REQUIRE(downstream_of_a.ok());
  FFD_CHECK_EQ(downstream_of_a.value().size(), std::size_t{3});
  FFD_CHECK(has(downstream_of_a.value(), d));

  const ffd::Result<std::vector<DomainId>> downstream_of_d = snapshot.downstream_exposure(d);
  FFD_REQUIRE(downstream_of_d.ok());
  FFD_CHECK(downstream_of_d.value().empty());

  // The whole chain shares no fate: exposure is one-directional.
  FFD_CHECK(snapshot.pair_verdict(a, d).value().verdict == ffd::PairVerdict::Unknown);
  FFD_CHECK_EQ(snapshot.upstream_exposure(DomainId{999}).code(), ffd::ErrorCode::UnknownDomain);
  FFD_CHECK_EQ(snapshot.pair_verdict(a, a).code(), ffd::ErrorCode::InvalidArgument);
}

FFD_TEST(jointly_exposed_resources_share_a_failure_domain) {
  Fixture fixture;
  const DomainId rack_a = fixture.create("rack-a");
  const DomainId rack_b = fixture.create("rack-b");
  const ffd::ExternalRef asset_1 = ffdtest::external("asset.registry", "asset-1");
  const ffd::ExternalRef asset_2 = ffdtest::external("asset.registry", "asset-2");
  const ffd::ExternalRef asset_3 = ffdtest::external("asset.registry", "asset-3");
  fixture.membership(rack_a, asset_1);
  fixture.membership(rack_a, asset_2);
  fixture.membership(rack_b, asset_3);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<ffd::ExternalRef>> joint =
      snapshot.jointly_exposed_resources({asset_1});
  FFD_REQUIRE(joint.ok());
  FFD_CHECK_EQ(joint.value().size(), std::size_t{1});
  FFD_CHECK(joint.value().front() == asset_2);

  const ffd::Result<std::vector<ffd::ExternalRef>> none =
      snapshot.jointly_exposed_resources({asset_1, asset_3});
  FFD_REQUIRE(none.ok());
  FFD_CHECK(none.value().empty());

  const ffd::Result<std::vector<DomainId>> containing = snapshot.containing_domains(asset_1);
  FFD_REQUIRE(containing.ok());
  FFD_CHECK_EQ(containing.value().size(), std::size_t{1});
  FFD_CHECK(containing.value().front() == rack_a);

  FFD_CHECK_EQ(snapshot.jointly_exposed_resources({}).code(), ffd::ErrorCode::InvalidArgument);
  const ffd::ExternalRef never = ffdtest::external("asset.registry", "never-declared");
  const ffd::Result<std::vector<ffd::ExternalRef>> empty =
      snapshot.jointly_exposed_resources({never});
  FFD_REQUIRE(empty.ok());
  FFD_CHECK(empty.value().empty());
}

FFD_TEST(shared_fate_group_follows_mutual_dependency) {
  Fixture fixture;
  const DomainId a = fixture.create("a", ffd::DomainClass::SharedService);
  const DomainId b = fixture.create("b", ffd::DomainClass::SharedService);
  const DomainId c = fixture.create("c", ffd::DomainClass::SharedService);
  fixture.dependency(a, b);
  fixture.dependency(b, a);
  fixture.dependency(b, c);
  fixture.dependency(c, b);

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<DomainId>> group = snapshot.shared_fate_group(a);
  FFD_REQUIRE(group.ok());
  FFD_CHECK_EQ(group.value().size(), std::size_t{2});
  FFD_CHECK(has(group.value(), b));
  FFD_CHECK(has(group.value(), c));
  FFD_CHECK(snapshot.pair_verdict(a, c).value().verdict == ffd::PairVerdict::ProvenSharedFate);
}

FFD_TEST(diagnostics_are_ordered_and_complete) {
  Fixture fixture;
  const DomainId dependent = fixture.create("service");
  const DomainId alias_one = fixture.create("ups-1", ffd::DomainClass::PowerSource);
  const DomainId alias_two = fixture.create("ups-2", ffd::DomainClass::PowerSource);
  const ffd::ExternalRef external_ups = ffdtest::external("dccp.topology", "ups-9");
  {
    ffd::DeclareDependencyRequest request;
    request.context = fixture.context();
    request.dependent = dependent;
    request.external_target = external_ups;
    FFD_REQUIRE(fixture.registry->declare_dependency(request).ok());
  }
  {
    ffd::DeclareAliasRequest request;
    request.context = fixture.context();
    request.domain = alias_two;
    request.resource = external_ups;
    FFD_REQUIRE(fixture.registry->declare_alias(request).ok());
  }
  {
    ffd::DeclareAliasRequest request;
    request.context = fixture.context();
    request.domain = alias_one;
    request.resource = external_ups;
    FFD_REQUIRE(fixture.registry->declare_alias(request).ok());
  }

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<ffd::UnresolvedReference>> unresolved =
      snapshot.unresolved_references();
  FFD_REQUIRE(unresolved.ok());
  FFD_REQUIRE(unresolved.value().size() == 1);
  FFD_CHECK(unresolved.value().front().state == ffd::ReferenceState::AmbiguousAlias);
  FFD_CHECK_EQ(unresolved.value().front().candidates.size(), std::size_t{2});
  FFD_CHECK(unresolved.value().front().candidates.front() == alias_one);
  FFD_CHECK(unresolved.value().front().candidates.back() == alias_two);

  const ffd::Result<std::vector<ffd::ConflictInfo>> conflicts = snapshot.conflicts();
  FFD_REQUIRE(conflicts.ok());
  FFD_REQUIRE(!conflicts.value().empty());
  FFD_CHECK(conflicts.value().front().kind == ffd::ConflictKind::AmbiguousAlias);

  // The rendering is deterministic and repeats byte for byte.
  const std::string first = snapshot.canonical_text();
  const std::string second = fixture.registry->snapshot().canonical_text();
  FFD_CHECK_EQ(first, second);
  FFD_CHECK(first.find("conflict ambiguous_alias") != std::string::npos);
  FFD_CHECK(first.find("unresolved ambiguous_alias") != std::string::npos);
}

FFD_TEST(content_digest_is_independent_of_declaration_order) {
  ffdtest::ScratchDir scratch{"query-order"};
  const auto build = [&](bool reversed) {
    ffd::StoreConfig config;
    config.path = scratch.file(reversed ? "reversed.ffdr" : "forward.ffdr");
    config.durability = ffd::Durability::ExplicitPublish;
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
    FFD_REQUIRE(registry.ok());
    ffd::CreateDomainRequest create;
    create.context = ffdtest::make_context("authority.alpha", 1, "c-1");
    create.domain_class = ffd::DomainClass::Rack;
    create.natural_key = "rack-1";
    const DomainId first = registry.value()->create_domain(create).value().domain;
    create.context = ffdtest::make_context("authority.alpha", 1, "c-2");
    create.natural_key = "rack-2";
    const DomainId second = registry.value()->create_domain(create).value().domain;

    // The same facts, declared in two different sequences.
    const auto declare_shared_fate = [&] {
      ffd::DeclareSharedFateRequest shared;
      shared.context = ffdtest::make_context("authority.alpha", 1, "s-1");
      shared.a = first;
      shared.b = second;
      FFD_REQUIRE(registry.value()->declare_shared_fate(shared).ok());
    };
    const auto declare_membership = [&] {
      ffd::AddMembershipRequest membership;
      membership.context = ffdtest::make_context("authority.alpha", 1, "m-1");
      membership.domain = second;
      membership.resource = ffdtest::external("asset.registry", "asset-1");
      FFD_REQUIRE(registry.value()->add_membership(membership).ok());
    };
    const auto declare_containment = [&] {
      ffd::DeclareContainmentRequest containment;
      containment.context = ffdtest::make_context("authority.alpha", 1, "n-1");
      containment.parent = first;
      containment.child = second;
      FFD_REQUIRE(registry.value()->declare_containment(containment).ok());
    };
    if (reversed) {
      declare_containment();
      declare_membership();
      declare_shared_fate();
    } else {
      declare_shared_fate();
      declare_membership();
      declare_containment();
    }
    return registry.value()->snapshot();
  };
  const ffd::Snapshot forward = build(false);
  const ffd::Snapshot reversed = build(true);
  FFD_CHECK(forward.digest() == reversed.digest());
  FFD_CHECK_EQ(strip_generation(forward.canonical_text()),
               strip_generation(reversed.canonical_text()));
}

FFD_TEST(evidence_reports_every_status) {
  Fixture fixture;
  const DomainId a = fixture.create("a");
  const DomainId b = fixture.create("b");
  fixture.shared_fate(a, b);
  {
    ffd::DeclareIndependenceRequest request;
    request.context = fixture.context("authority.beta");
    request.a = a;
    request.b = b;
    FFD_REQUIRE(fixture.registry->declare_independence(request).ok());
  }
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  ffd::ClaimRef claim;
  claim.kind = ffd::FactKind::Independence;
  claim.subject = a < b ? a : b;
  claim.object = a < b ? b : a;
  const ffd::Result<std::vector<ffd::FactEvidence>> evidence = snapshot.evidence_for(claim);
  FFD_REQUIRE(evidence.ok());
  FFD_REQUIRE(!evidence.value().empty());
  for (const ffd::FactEvidence& item : evidence.value()) {
    FFD_CHECK(item.kind == ffd::FactKind::Independence);
    FFD_CHECK(item.status == ffd::FactStatus::Effective ||
              item.status == ffd::FactStatus::Conflicting);
  }
  const ffd::PairVerdictResult verdict = snapshot.pair_verdict(a, b).value();
  FFD_CHECK(verdict.verdict == ffd::PairVerdict::Conflicting);
  FFD_CHECK(!verdict.explanation.empty());

  ffd::ClaimRef unknown;
  unknown.kind = ffd::FactKind::Membership;
  unknown.subject = a;
  unknown.external = ffdtest::external("asset.registry", "nothing");
  const ffd::Result<std::vector<ffd::FactEvidence>> none = snapshot.evidence_for(unknown);
  FFD_REQUIRE(none.ok());
  FFD_CHECK(none.value().empty());
}
