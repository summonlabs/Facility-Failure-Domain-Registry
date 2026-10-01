// Facility Failure Domain Registry - end-to-end facility lifecycle test.
//
// Builds one realistic facility model, publishes it, hands an exact model
// binding to a downstream consumer, and proves that the consumer can detect
// staleness and that the journal survives an independent process restart.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;

std::string read_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

struct Facility {
  ffdtest::ScratchDir scratch{"lifecycle"};
  std::unique_ptr<ffd::Registry> registry;
  std::uint64_t counter{0};

  DomainId hall;
  DomainId room;
  DomainId row_a;
  DomainId row_b;
  DomainId rack_a1;
  DomainId rack_a2;
  DomainId rack_b1;
  DomainId pdu_a;
  DomainId pdu_b;
  DomainId cooling_loop;
  DomainId switch_service;
  DomainId ups;

  Facility() {
    ffd::StoreConfig config;
    config.path = scratch.file("facility.ffdr");
    config.durability = ffd::Durability::DurablePerMutation;
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::move(opened.value());
    build();
  }

  [[nodiscard]] ffd::MutationContext context(const char* who = "dccp.topology") {
    return ffdtest::make_context(who, 1, ffdtest::index_key("f", ++counter));
  }

  DomainId add(const std::string& key, ffd::DomainClass domain_class) {
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

  void contains(DomainId parent, DomainId child) {
    ffd::DeclareContainmentRequest request;
    request.context = context();
    request.parent = parent;
    request.child = child;
    FFD_REQUIRE(registry->declare_containment(request).ok());
  }

  void depends_on(DomainId dependent, DomainId target) {
    ffd::DeclareDependencyRequest request;
    request.context = context();
    request.dependent = dependent;
    request.target = target;
    FFD_REQUIRE(registry->declare_dependency(request).ok());
  }

  void shares_fate(DomainId a, DomainId b, const char* who = "dccp.topology") {
    ffd::DeclareSharedFateRequest request;
    request.context = context(who);
    request.a = a;
    request.b = b;
    FFD_REQUIRE(registry->declare_shared_fate(request).ok());
  }

  void member_of(DomainId domain, const char* owner, const std::string& resource) {
    ffd::AddMembershipRequest request;
    request.context = context();
    request.domain = domain;
    request.resource = ffdtest::external(owner, resource);
    FFD_REQUIRE(registry->add_membership(request).ok());
  }

  void build() {
    hall = add("hall-1", ffd::DomainClass::Hall);
    room = add("room-1", ffd::DomainClass::Room);
    row_a = add("row-a", ffd::DomainClass::Row);
    row_b = add("row-b", ffd::DomainClass::Row);
    rack_a1 = add("rack-a1", ffd::DomainClass::Rack);
    rack_a2 = add("rack-a2", ffd::DomainClass::Rack);
    rack_b1 = add("rack-b1", ffd::DomainClass::Rack);
    pdu_a = add("pdu-a", ffd::DomainClass::PowerDistribution);
    pdu_b = add("pdu-b", ffd::DomainClass::PowerDistribution);
    ups = add("ups-1", ffd::DomainClass::PowerSource);
    cooling_loop = add("cooling-loop-1", ffd::DomainClass::CoolingDistribution);
    switch_service = add("switch-1", ffd::DomainClass::SharedService);

    contains(hall, room);
    contains(room, row_a);
    contains(room, row_b);
    contains(row_a, rack_a1);
    contains(row_a, rack_a2);
    contains(row_b, rack_b1);

    // Power: both PDUs draw from the same UPS, which therefore shares their fate.
    depends_on(pdu_a, ups);
    depends_on(pdu_b, ups);
    shares_fate(pdu_a, pdu_b);
    depends_on(rack_a1, pdu_a);
    depends_on(rack_a2, pdu_a);
    depends_on(rack_b1, pdu_b);

    // Cooling and network are shared services for every rack.
    depends_on(rack_a1, cooling_loop);
    depends_on(rack_a2, cooling_loop);
    depends_on(rack_b1, cooling_loop);
    depends_on(rack_a1, switch_service);
    depends_on(rack_a2, switch_service);
    depends_on(rack_b1, switch_service);

    // Assets are opaque identities owned by the asset registry.
    member_of(rack_a1, "asset.registry", "asset-1001");
    member_of(rack_a1, "asset.registry", "asset-1002");
    member_of(rack_a2, "asset.registry", "asset-1003");
    member_of(rack_b1, "asset.registry", "asset-1004");
  }
};

}  // namespace

FFD_TEST(facility_lifecycle_from_publication_to_downstream_binding) {
  Facility facility;
  const ffd::Snapshot published = facility.registry->snapshot();
  const ffd::ModelBinding binding = published.binding();
  FFD_CHECK(binding.generation > 0);
  FFD_CHECK(!binding.digest.is_zero());
  FFD_CHECK_EQ(published.domain_count(), std::size_t{12});

  // A downstream decision binds to the exact published model.
  FFD_REQUIRE(published.verify_binding(binding).ok());

  // A PDU-A failure exposes the racks that draw from it, the sibling PDU that
  // shares its fate, and in turn the racks fed by that sibling.
  const ffd::Result<std::vector<DomainId>> exposed = published.downstream_exposure(facility.pdu_a);
  FFD_REQUIRE(exposed.ok());
  FFD_CHECK_EQ(exposed.value().size(), std::size_t{4});
  for (const DomainId expected : {facility.rack_a1, facility.rack_a2, facility.pdu_b,
                                  facility.rack_b1}) {
    FFD_CHECK(std::find(exposed.value().begin(), exposed.value().end(), expected) !=
              exposed.value().end());
  }

  // Assets sharing a failure domain with asset-1001: its neighbour in rack-a1.
  const ffd::Result<std::vector<ffd::ExternalRef>> jointly =
      published.jointly_exposed_resources({ffdtest::external("asset.registry", "asset-1001")});
  FFD_REQUIRE(jointly.ok());
  FFD_CHECK_EQ(jointly.value().size(), std::size_t{1});
  FFD_CHECK(jointly.value().front() == ffdtest::external("asset.registry", "asset-1002"));

  // Both PDUs share the UPS fate transitively through the shared-fate claim.
  FFD_CHECK(published.pair_verdict(facility.pdu_a, facility.pdu_b).value().verdict ==
            ffd::PairVerdict::ProvenSharedFate);
  // Racks on different rows are not proven independent, but they are not proven
  // shared-fate either: the answer stays unknown.
  FFD_CHECK(published.pair_verdict(facility.rack_a1, facility.rack_b1).value().verdict ==
            ffd::PairVerdict::Unknown);

  // The model is durable and readable by an independent process.
  const std::filesystem::path out = facility.scratch.file("inspect.out");
  ffdtest::ChildProcess inspector;
  FFD_REQUIRE(ffdtest::ChildProcess::spawn(
      {"inspect", facility.scratch.file("facility.ffdr").string(), out.string()}, inspector));
  FFD_CHECK_EQ(inspector.wait(), 0);
  const std::string report = read_text(out);
  FFD_CHECK(report.find("GEN " + std::to_string(binding.generation)) != std::string::npos);
  FFD_CHECK(report.find(binding.digest.hex()) != std::string::npos);

  // The facility changes; the previously bound model is now stale, and the same
  // decision can be re-run against the new generation explicitly.
  ffd::RetireDomainRequest retire;
  retire.context = facility.context();
  retire.domain = facility.rack_b1;
  retire.reason = "decommissioned";
  FFD_REQUIRE(facility.registry->retire_domain(retire).ok());
  const ffd::Snapshot current = facility.registry->snapshot();
  FFD_CHECK_EQ(current.verify_binding(binding).code(), ffd::ErrorCode::StaleGeneration);
  FFD_CHECK(!(current.digest() == binding.digest));
  FFD_CHECK(current.verify_binding(current.binding()).ok());
}

FFD_TEST(lifecycle_replacement_keeps_history_and_rejects_stale_consumers) {
  Facility facility;
  const ffd::ModelBinding before = facility.registry->snapshot().binding();

  // Replace a failed rack: the successor is a new identity, the predecessor
  // keeps its history, and the replacement inherits nothing implicitly.
  ffd::SupersedeDomainRequest supersede;
  supersede.context = facility.context("dccp.operations");
  supersede.predecessor = facility.rack_a2;
  supersede.domain_class = ffd::DomainClass::Rack;
  supersede.natural_key = "rack-a2-replacement";
  supersede.display_name = "replacement rack";
  const ffd::Result<ffd::MutationOutcome> replaced = facility.registry->supersede_domain(supersede);
  FFD_REQUIRE(replaced.ok());
  const DomainId replacement = replaced.value().domain;

  const ffd::Snapshot snapshot = facility.registry->snapshot();
  const ffd::DomainInfo predecessor = snapshot.domain(facility.rack_a2).value();
  FFD_CHECK(predecessor.lifecycle == ffd::DomainLifecycle::Superseded);
  FFD_CHECK(predecessor.successor == replacement);
  FFD_CHECK(snapshot.domain(replacement).value().lifecycle == ffd::DomainLifecycle::Active);

  // Assets still point at the old identity until an operator re-declares them.
  const ffd::Result<std::vector<DomainId>> containing_old =
      snapshot.containing_domains(ffdtest::external("asset.registry", "asset-1003"));
  FFD_REQUIRE(containing_old.ok());
  FFD_CHECK(containing_old.value().empty());
  FFD_CHECK(snapshot.containing_domains(ffdtest::external("asset.registry", "asset-1003"), true)
                .value()
                .size() == 1);

  // The replaced rack is no longer part of current exposure.
  FFD_CHECK_EQ(snapshot.downstream_exposure(facility.rack_a2).code(),
               ffd::ErrorCode::DomainNotActive);
  FFD_CHECK(snapshot.verify_binding(before).code() == ffd::ErrorCode::StaleGeneration);
}

FFD_TEST(idempotent_operations_survive_process_restart) {
  Facility facility;
  const std::filesystem::path store = facility.scratch.file("facility.ffdr");
  ffd::CreateDomainRequest request;
  request.context = ffdtest::make_context("dccp.topology", 1, "restart-stable-operation");
  request.domain_class = ffd::DomainClass::Rack;
  request.natural_key = "rack-restart";
  const ffd::Result<ffd::MutationOutcome> first = facility.registry->create_domain(request);
  FFD_REQUIRE(first.ok());
  const ffd::ModelBinding binding = facility.registry->snapshot().binding();
  facility.registry.reset();

  ffd::StoreConfig config;
  config.path = store;
  config.durability = ffd::Durability::DurablePerMutation;
  ffd::Result<std::unique_ptr<ffd::Registry>> reopened = ffd::Registry::open(config);
  FFD_REQUIRE(reopened.ok());
  FFD_CHECK(reopened.value()->snapshot().verify_binding(binding).ok());
  const ffd::Result<ffd::MutationOutcome> replay = reopened.value()->create_domain(request);
  FFD_REQUIRE(replay.ok());
  FFD_CHECK(replay.value().replayed);
  FFD_CHECK(replay.value().domain == first.value().domain);
  FFD_CHECK_EQ(reopened.value()->generation(), first.value().generation);
}

FFD_TEST(canonical_rendering_matches_the_published_digest) {
  Facility facility;
  const ffd::Snapshot snapshot = facility.registry->snapshot();
  const std::string text = snapshot.canonical_text();
  FFD_CHECK(text.find("digest " + snapshot.digest().hex()) != std::string::npos);
  FFD_CHECK(text.find("domain ") != std::string::npos);
  FFD_CHECK(text.find("edge ") != std::string::npos);
  // Reopening the durable store reproduces the same rendering exactly.
  const std::filesystem::path store = facility.scratch.file("facility.ffdr");
  facility.registry.reset();
  ffd::StoreConfig config;
  config.path = store;
  ffd::Result<ffd::Snapshot> loaded = ffd::load_snapshot(config);
  FFD_REQUIRE(loaded.ok());
  FFD_CHECK(loaded.value().digest() == snapshot.digest());
  FFD_CHECK_EQ(loaded.value().canonical_text(), text);
}
