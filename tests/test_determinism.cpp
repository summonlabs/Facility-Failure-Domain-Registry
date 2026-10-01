// Facility Failure Domain Registry - determinism, idempotency and replay tests.
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
  ffdtest::ScratchDir scratch{"determinism"};
  std::shared_ptr<ffd::Registry> registry;
  std::uint64_t counter{0};
  ffd::StoreConfig config;

  explicit Fixture(ffd::Durability durability = ffd::Durability::DurablePerMutation) {
    config.path = scratch.file("store.ffdr");
    config.durability = durability;
    reopen();
  }

  void reopen() {
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::shared_ptr<ffd::Registry>(std::move(opened.value()));
  }

  void close() { registry.reset(); }

  [[nodiscard]] ffd::CreateDomainRequest request(const std::string& key, const char* who = "authority.alpha",
                                                const std::string& idempotency = std::string()) {
    ffd::CreateDomainRequest create;
    create.context = ffdtest::make_context(who, 1,
                                          idempotency.empty() ? ffdtest::index_key("k", ++counter)
                                                              : idempotency);
    create.domain_class = ffd::DomainClass::Rack;
    create.natural_key = key;
    return create;
  }
};

}  // namespace

FFD_TEST(replay_returns_the_recorded_outcome) {
  Fixture fixture;
  ffd::CreateDomainRequest create = fixture.request("rack-1", "authority.alpha", "operation-1");
  const ffd::Result<ffd::MutationOutcome> first = fixture.registry->create_domain(create);
  FFD_REQUIRE(first.ok());
  FFD_CHECK(!first.value().replayed);
  const std::uint64_t generation = fixture.registry->generation();
  const ffd::Digest digest = fixture.registry->digest();

  // The same operation arrives again: same answer, no second effect.
  const ffd::Result<ffd::MutationOutcome> second = fixture.registry->create_domain(create);
  FFD_REQUIRE(second.ok());
  FFD_CHECK(second.value().replayed);
  FFD_CHECK_EQ(second.value().generation, generation);
  FFD_CHECK(second.value().digest == digest);
  FFD_CHECK(second.value().domain == first.value().domain);
  FFD_CHECK_EQ(fixture.registry->generation(), generation);
  FFD_CHECK_EQ(fixture.registry->snapshot().domain_count(), std::size_t{1});

  // Reusing the key for a different operation is refused.
  ffd::CreateDomainRequest different = fixture.request("rack-2", "authority.alpha", "operation-1");
  const ffd::Result<ffd::MutationOutcome> third = fixture.registry->create_domain(different);
  FFD_REQUIRE(!third.ok());
  FFD_CHECK_EQ(third.error().code, ffd::ErrorCode::IdempotencyKeyReuse);
}

FFD_TEST(replay_survives_restart_and_outranks_a_stale_precondition) {
  Fixture fixture;
  ffd::CreateDomainRequest create = fixture.request("rack-1", "authority.alpha", "operation-7");
  FFD_REQUIRE(fixture.registry->create_domain(create).ok());
  const std::uint64_t recorded_generation = fixture.registry->generation();
  const ffd::Digest recorded_digest = fixture.registry->digest();
  for (int i = 0; i < 3; ++i) {
    FFD_REQUIRE(fixture.registry->create_domain(fixture.request("later-" + std::to_string(i))).ok());
  }
  FFD_CHECK_EQ(fixture.registry->generation(), recorded_generation + 3);
  fixture.close();
  fixture.reopen();

  // The retry carries a precondition that is now stale. It is still resolved as
  // a replay first, because the operation is demonstrably already committed.
  create.context.expected_generation = recorded_generation;
  const ffd::Result<ffd::MutationOutcome> replay = fixture.registry->create_domain(create);
  FFD_REQUIRE(replay.ok());
  FFD_CHECK(replay.value().replayed);
  FFD_CHECK_EQ(replay.value().generation, recorded_generation);
  FFD_CHECK(replay.value().digest == recorded_digest);
  FFD_CHECK_EQ(fixture.registry->generation(), recorded_generation + 3);

  // The same precondition without a matching key is a genuine stale write.
  ffd::CreateDomainRequest fresh = fixture.request("rack-9");
  fresh.context.expected_generation = recorded_generation;
  const ffd::Result<ffd::MutationOutcome> stale = fixture.registry->create_domain(fresh);
  FFD_REQUIRE(!stale.ok());
  FFD_CHECK_EQ(stale.error().code, ffd::ErrorCode::StaleGeneration);
}

FFD_TEST(keyless_mutations_when_the_store_allows_them) {
  ffdtest::ScratchDir scratch{"determinism-keyless"};
  ffd::StoreConfig config;
  config.path = scratch.file("store.ffdr");
  config.durability = ffd::Durability::DurablePerMutation;
  config.key_policy = ffd::MutationKeyPolicy::Optional;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
  FFD_REQUIRE(registry.ok());
  ffd::CreateDomainRequest create;
  create.context = ffdtest::make_context_without_key("authority.alpha", 1);
  create.natural_key = "rack-1";
  FFD_CHECK(registry.value()->create_domain(create).ok());
  ffd::CreateDomainRequest duplicate = create;
  const ffd::Result<ffd::MutationOutcome> again = registry.value()->create_domain(duplicate);
  FFD_REQUIRE(!again.ok());
  FFD_CHECK_EQ(again.error().code, ffd::ErrorCode::DuplicateNaturalKey);
}

FFD_TEST(digest_depends_on_content_not_on_declaration_order) {
  ffdtest::ScratchDir scratch{"determinism-order"};
  const auto build = [&](const std::vector<int>& order) {
    ffd::StoreConfig config;
    config.path = scratch.file("order-" + std::to_string(order.front()) + ".ffdr");
    config.durability = ffd::Durability::ExplicitPublish;
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
    FFD_REQUIRE(registry.ok());
    std::uint64_t step = 0;
    const auto next = [&] { return ffdtest::make_context("authority.alpha", 1,
                                                         ffdtest::index_key("s", ++step)); };
    for (const int operation : order) {
      switch (operation) {
        case 0: {
          const ffd::DomainId ids[4] = {DomainId{1}, DomainId{2}, DomainId{3}, DomainId{4}};
          const ffd::DomainClass classes[4] = {ffd::DomainClass::Room, ffd::DomainClass::Row,
                                               ffd::DomainClass::Rack, ffd::DomainClass::PowerDistribution};
          const char* keys[4] = {"room-a", "row-1", "rack-1", "pdu-1"};
          for (int i = 0; i < 4; ++i) {
            ffd::CreateDomainRequest create;
            create.context = next();
            create.domain_class = classes[i];
            create.natural_key = keys[i];
            create.requested_id = ids[i];
            FFD_REQUIRE(registry.value()->create_domain(create).ok());
          }
          break;
        }
        case 1: {
          ffd::DeclareContainmentRequest containment;
          containment.context = next();
          containment.parent = DomainId{1};
          containment.child = DomainId{2};
          FFD_REQUIRE(registry.value()->declare_containment(containment).ok());
          break;
        }
        case 2: {
          ffd::DeclareContainmentRequest containment;
          containment.context = next();
          containment.parent = DomainId{2};
          containment.child = DomainId{3};
          FFD_REQUIRE(registry.value()->declare_containment(containment).ok());
          break;
        }
        case 3: {
          ffd::AddMembershipRequest membership;
          membership.context = next();
          membership.domain = DomainId{3};
          membership.resource = ffdtest::external("asset.registry", "asset-1");
          FFD_REQUIRE(registry.value()->add_membership(membership).ok());
          break;
        }
        case 4: {
          ffd::DeclareDependencyRequest dependency;
          dependency.context = next();
          dependency.dependent = DomainId{3};
          dependency.target = DomainId{4};
          FFD_REQUIRE(registry.value()->declare_dependency(dependency).ok());
          break;
        }
        case 5: {
          ffd::DeclareIndependenceRequest independence;
          independence.context = next();
          independence.a = DomainId{1};
          independence.b = DomainId{4};
          FFD_REQUIRE(registry.value()->declare_independence(independence).ok());
          break;
        }
        default: {
          ffd::DeclareSharedFateRequest shared;
          shared.context = next();
          shared.a = DomainId{4};
          shared.b = DomainId{2};
          FFD_REQUIRE(registry.value()->declare_shared_fate(shared).ok());
          break;
        }
      }
    }
    return registry.value()->snapshot();
  };
  // Domains first, then the declarations in two different sequences.
  const ffd::Snapshot forward = build({0, 1, 2, 3, 4, 5, 6});
  const ffd::Snapshot shuffled = build({0, 6, 5, 4, 3, 2, 1});
  FFD_CHECK(forward.digest() == shuffled.digest());
  FFD_CHECK_EQ(forward.canonical_text().substr(forward.canonical_text().find('\n')),
               shuffled.canonical_text().substr(shuffled.canonical_text().find('\n')));
}

FFD_TEST(reload_preserves_generation_and_digest) {
  Fixture fixture;
  for (int i = 0; i < 5; ++i) {
    FFD_REQUIRE(fixture.registry->create_domain(fixture.request("rack-" + std::to_string(i))).ok());
  }
  const std::uint64_t generation = fixture.registry->generation();
  const ffd::Digest digest = fixture.registry->digest();
  const std::size_t facts = fixture.registry->snapshot().fact_count();
  for (int cycle = 0; cycle < 5; ++cycle) {
    fixture.close();
    fixture.reopen();
    FFD_CHECK_EQ(fixture.registry->generation(), generation);
    FFD_CHECK(fixture.registry->digest() == digest);
    FFD_CHECK_EQ(fixture.registry->snapshot().fact_count(), facts);
  }
}

FFD_TEST(idempotency_journal_eviction_is_bounded_and_explicit) {
  ffdtest::ScratchDir scratch{"determinism-journal"};
  ffd::StoreConfig config;
  config.path = scratch.file("store.ffdr");
  config.durability = ffd::Durability::DurablePerMutation;
  config.limits.max_idempotency_entries = 2;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
  FFD_REQUIRE(registry.ok());
  for (int i = 0; i < 3; ++i) {
    ffd::CreateDomainRequest create;
    create.context = ffdtest::make_context("authority.alpha", 1,
                                          ffdtest::index_key("evict", static_cast<std::uint64_t>(i)));
    create.natural_key = "rack-" + std::to_string(i);
    FFD_REQUIRE(registry.value()->create_domain(create).ok());
  }
  // The oldest key was evicted, so it is no longer recognised as a replay and
  // the underlying duplicate is refused instead.
  ffd::CreateDomainRequest replayed;
  replayed.context = ffdtest::make_context("authority.alpha", 1, "evict-0");
  replayed.natural_key = "rack-0";
  const ffd::Result<ffd::MutationOutcome> outcome = registry.value()->create_domain(replayed);
  FFD_REQUIRE(!outcome.ok());
  FFD_CHECK_EQ(outcome.error().code, ffd::ErrorCode::DuplicateNaturalKey);

  // The most recent key is still recognised.
  ffd::CreateDomainRequest recent;
  recent.context = ffdtest::make_context("authority.alpha", 1, "evict-2");
  recent.natural_key = "rack-2";
  const ffd::Result<ffd::MutationOutcome> replay = registry.value()->create_domain(recent);
  FFD_REQUIRE(replay.ok());
  FFD_CHECK(replay.value().replayed);
}

FFD_TEST(query_results_are_ordered_by_stable_identity) {
  Fixture fixture;
  const DomainId first = fixture.registry->create_domain(fixture.request("rack-1")).value().domain;
  const DomainId second = fixture.registry->create_domain(fixture.request("rack-2")).value().domain;
  const DomainId third = fixture.registry->create_domain(fixture.request("rack-3")).value().domain;
  // Declared from the newest to the oldest: the answer is still ordered by id.
  for (const DomainId child : {third, second, first}) {
    ffd::AddMembershipRequest membership;
    membership.context = ffdtest::make_context("authority.alpha", 1,
                                              ffdtest::index_key("m", ++fixture.counter));
    membership.domain = child;
    membership.resource = ffdtest::external("asset.registry", "shared-asset");
    FFD_REQUIRE(fixture.registry->add_membership(membership).ok());
  }
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<DomainId>> containing =
      snapshot.containing_domains(ffdtest::external("asset.registry", "shared-asset"));
  FFD_REQUIRE(containing.ok());
  FFD_REQUIRE(containing.value().size() == 3);
  FFD_CHECK(containing.value()[0] == first);
  FFD_CHECK(containing.value()[1] == second);
  FFD_CHECK(containing.value()[2] == third);
  for (std::size_t i = 1; i < containing.value().size(); ++i) {
    FFD_CHECK(containing.value()[i - 1] < containing.value()[i]);
  }
}
