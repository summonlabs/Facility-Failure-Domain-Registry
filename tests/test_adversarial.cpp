// Facility Failure Domain Registry - adversarial hardening tests.
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "ffd/registry.hpp"
#include "storage.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;

struct Fixture {
  ffdtest::ScratchDir scratch{"adversarial"};
  std::unique_ptr<ffd::Registry> registry;
  std::uint64_t counter{0};
  ffd::StoreConfig config;

  explicit Fixture(ffd::Durability durability = ffd::Durability::ExplicitPublish) {
    config.path = scratch.file("store.ffdr");
    config.durability = durability;
    open();
  }

  void open() {
    ffd::Result<std::unique_ptr<ffd::Registry>> opened = ffd::Registry::open(config);
    if (!opened.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + opened.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    registry = std::move(opened.value());
  }

  [[nodiscard]] ffd::MutationContext context(const char* who = "authority.alpha") {
    return ffdtest::make_context(who, 1, ffdtest::index_key("a", ++counter));
  }

  DomainId create(const std::string& key,
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
};

void expect_code(const ffd::Result<ffd::MutationOutcome>& result, ffd::ErrorCode expected,
                 const char* what) {
  if (result.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__, std::string(what) + " unexpectedly succeeded");
    return;
  }
  if (result.code() != expected) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + " produced " + ffd::to_string(result.code()) +
                                  " instead of " + ffd::to_string(expected));
  }
}

}  // namespace

FFD_TEST(malformed_identities_are_refused) {
  Fixture fixture;
  const ffd::DomainId rack = fixture.create("rack-1");

  const std::string invalid_utf8 = std::string("rack-") + '\xc3';
  ffd::CreateDomainRequest bad_key;
  bad_key.context = fixture.context();
  bad_key.natural_key = invalid_utf8;
  expect_code(fixture.registry->create_domain(bad_key), ffd::ErrorCode::InvalidArgument,
              "invalid utf-8 natural key");

  ffd::CreateDomainRequest oversize;
  oversize.context = fixture.context();
  oversize.natural_key = std::string(1000, 'k');
  expect_code(fixture.registry->create_domain(oversize), ffd::ErrorCode::LimitExceeded,
              "oversized natural key");

  ffd::CreateDomainRequest padded;
  padded.context = fixture.context();
  padded.natural_key = " rack-2";
  expect_code(fixture.registry->create_domain(padded), ffd::ErrorCode::InvalidArgument,
              "padded natural key");

  ffd::CreateDomainRequest control;
  control.context = fixture.context();
  control.natural_key = std::string("rack") + '\x07';
  expect_code(fixture.registry->create_domain(control), ffd::ErrorCode::InvalidArgument,
              "control character in natural key");

  ffd::CreateDomainRequest unknown_class;
  unknown_class.context = fixture.context();
  unknown_class.natural_key = "rack-3";
  unknown_class.domain_class = static_cast<ffd::DomainClass>(77);
  expect_code(fixture.registry->create_domain(unknown_class), ffd::ErrorCode::InvalidArgument,
              "unknown domain class");

  ffd::AddMembershipRequest bad_authority;
  bad_authority.context = fixture.context();
  bad_authority.domain = rack;
  bad_authority.resource = ffdtest::external("bad authority", "asset-1");
  expect_code(fixture.registry->add_membership(bad_authority), ffd::ErrorCode::InvalidArgument,
              "authority with a space");

  ffd::AddMembershipRequest bad_evidence;
  bad_evidence.context = fixture.context();
  bad_evidence.context.provenance.evidence = std::string(1000, 'e');
  bad_evidence.domain = rack;
  bad_evidence.resource = ffdtest::external("asset.registry", "asset-1");
  expect_code(fixture.registry->add_membership(bad_evidence), ffd::ErrorCode::LimitExceeded,
              "oversized evidence");

  const ffd::DomainId other = fixture.create("rack-other");
  ffd::DeclareIndependenceRequest bad_key_value;
  bad_key_value.context = fixture.context();
  bad_key_value.context.key->value = "not a valid key";
  bad_key_value.a = rack;
  bad_key_value.b = other;
  expect_code(fixture.registry->declare_independence(bad_key_value), ffd::ErrorCode::InvalidArgument,
              "idempotency key with spaces");

  // Valid multi-byte UTF-8 is accepted and round-trips.
  const ffd::DomainId unicode = fixture.create("rack-\xc3\xa9\xe2\x82\xac");
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  FFD_CHECK_EQ(snapshot.domain(unicode).value().natural_key,
               std::string("rack-\xc3\xa9\xe2\x82\xac"));
}

FFD_TEST(self_references_and_cycles_are_refused) {
  Fixture fixture;
  const DomainId a = fixture.create("a");
  const DomainId b = fixture.create("b");
  const DomainId c = fixture.create("c");

  {
    ffd::DeclareDependencyRequest request;
    request.context = fixture.context();
    request.dependent = a;
    request.target = a;
    expect_code(fixture.registry->declare_dependency(request), ffd::ErrorCode::SelfReference,
                "self dependency");
  }
  {
    ffd::DeclareSharedFateRequest request;
    request.context = fixture.context();
    request.a = a;
    request.b = a;
    expect_code(fixture.registry->declare_shared_fate(request), ffd::ErrorCode::SelfReference,
                "self shared fate");
  }
  {
    ffd::DeclareIndependenceRequest request;
    request.context = fixture.context();
    request.a = a;
    request.b = a;
    expect_code(fixture.registry->declare_independence(request), ffd::ErrorCode::SelfReference,
                "impossible independence");
  }
  {
    ffd::DeclareDependencyRequest request;
    request.context = fixture.context();
    request.dependent = a;
    expect_code(fixture.registry->declare_dependency(request), ffd::ErrorCode::InvalidArgument,
                "dependency without a target");
  }
  {
    ffd::DeclareDependencyRequest request;
    request.context = fixture.context();
    request.dependent = a;
    request.target = b;
    request.external_target = ffdtest::external("asset.registry", "asset-1");
    expect_code(fixture.registry->declare_dependency(request), ffd::ErrorCode::InvalidArgument,
                "dependency with two targets");
  }
  // A long containment cycle is refused and leaves the model untouched.
  ffd::DeclareContainmentRequest chain;
  chain.context = fixture.context();
  chain.parent = a;
  chain.child = b;
  FFD_REQUIRE(fixture.registry->declare_containment(chain).ok());
  chain.context = fixture.context();
  chain.parent = b;
  chain.child = c;
  FFD_REQUIRE(fixture.registry->declare_containment(chain).ok());
  const std::uint64_t generation = fixture.registry->generation();
  chain.context = fixture.context();
  chain.parent = c;
  chain.child = a;
  expect_code(fixture.registry->declare_containment(chain), ffd::ErrorCode::CycleNotAllowed,
              "containment cycle");
  FFD_CHECK_EQ(fixture.registry->generation(), generation);

  // Supersession cycles are refused as well.
  {
    ffd::SupersedeDomainRequest supersede;
    supersede.context = fixture.context();
    supersede.predecessor = a;
    supersede.natural_key = "a-replacement";
    FFD_REQUIRE(fixture.registry->supersede_domain(supersede).ok());
  }
}

FFD_TEST(retraction_of_retraction_is_refused) {
  Fixture fixture;
  const DomainId rack = fixture.create("rack-1");
  ffd::ClaimRef retraction_of_retraction;
  retraction_of_retraction.kind = ffd::FactKind::Retraction;
  retraction_of_retraction.target_kind = ffd::FactKind::Retraction;
  retraction_of_retraction.subject = rack;
  retraction_of_retraction.target_authority = ffdtest::authority("authority.beta");
  ffd::RevokeClaimRequest request;
  request.context = fixture.context();
  request.claim = retraction_of_retraction;
  expect_code(fixture.registry->revoke_claim(request), ffd::ErrorCode::InvalidArgument,
              "retraction of a retraction");

  ffd::ClaimRef without_authority;
  without_authority.kind = ffd::FactKind::Retirement;
  without_authority.subject = rack;
  request.context = fixture.context();
  request.claim = without_authority;
  expect_code(fixture.registry->revoke_claim(request), ffd::ErrorCode::InvalidArgument,
              "retraction without a target authority");
}

FFD_TEST(wide_and_deep_models_stay_bounded) {
  Fixture fixture;
  const ffd::DomainId parent = fixture.create("parent", ffd::DomainClass::Room);
  constexpr int kWide = 400;
  std::vector<DomainId> children;
  children.reserve(kWide);
  for (int i = 0; i < kWide; ++i) {
    children.push_back(fixture.create("child-" + std::to_string(i), ffd::DomainClass::Rack));
  }
  for (const DomainId child : children) {
    ffd::DeclareContainmentRequest containment;
    containment.context = fixture.context();
    containment.parent = parent;
    containment.child = child;
    FFD_REQUIRE(fixture.registry->declare_containment(containment).ok());
  }
  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<DomainId>> downstream = snapshot.downstream_exposure(parent);
  FFD_REQUIRE(downstream.ok());
  FFD_CHECK_EQ(downstream.value().size(), std::size_t{kWide});
  FFD_CHECK(std::is_sorted(downstream.value().begin(), downstream.value().end()));

  // A long dependency chain is resolved iteratively.
  constexpr int kDeep = 1500;
  std::vector<DomainId> chain;
  chain.reserve(kDeep);
  for (int i = 0; i < kDeep; ++i) {
    chain.push_back(fixture.create("service-" + std::to_string(i), ffd::DomainClass::SharedService));
  }
  for (int i = 1; i < kDeep; ++i) {
    ffd::DeclareDependencyRequest dependency;
    dependency.context = fixture.context();
    dependency.dependent = chain[static_cast<std::size_t>(i)];
    dependency.target = chain[static_cast<std::size_t>(i - 1)];
    FFD_REQUIRE(fixture.registry->declare_dependency(dependency).ok());
  }
  const ffd::Snapshot deep_snapshot = fixture.registry->snapshot();
  const ffd::Result<std::vector<DomainId>> upstream =
      deep_snapshot.upstream_exposure(chain.back());
  FFD_REQUIRE(upstream.ok());
  FFD_CHECK_EQ(upstream.value().size(), std::size_t{kDeep - 1});
}

FFD_TEST(identity_space_exhaustion_is_refused) {
  Fixture fixture;
  ffd::CreateDomainRequest extreme;
  extreme.context = fixture.context();
  extreme.natural_key = "last-identity";
  extreme.requested_id = DomainId{(std::numeric_limits<std::uint64_t>::max)()};
  FFD_REQUIRE(fixture.registry->create_domain(extreme).ok());
  ffd::CreateDomainRequest overflow;
  overflow.context = fixture.context();
  overflow.natural_key = "beyond-last-identity";
  expect_code(fixture.registry->create_domain(overflow), ffd::ErrorCode::Overflow,
              "identity space exhaustion");
}

FFD_TEST(repeated_open_close_cycles_are_stable) {
  Fixture fixture(ffd::Durability::DurablePerMutation);
  for (int i = 0; i < 6; ++i) {
    fixture.create("rack-" + std::to_string(i));
  }
  const std::uint64_t generation = fixture.registry->generation();
  const ffd::Digest digest = fixture.registry->digest();
  for (int cycle = 0; cycle < 40; ++cycle) {
    fixture.registry.reset();
    fixture.open();
    FFD_CHECK_EQ(fixture.registry->generation(), generation);
    FFD_CHECK(fixture.registry->digest() == digest);
  }
}

FFD_TEST(concurrent_mutation_is_serialised_and_consistent) {
  Fixture fixture(ffd::Durability::ExplicitPublish);
  constexpr int kThreads = 4;
  constexpr int kPerThread = 25;
  std::atomic<int> failures{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int thread = 0; thread < kThreads; ++thread) {
    threads.emplace_back([&, thread] {
      for (int i = 0; i < kPerThread; ++i) {
        ffd::CreateDomainRequest request;
        request.context = ffdtest::make_context(
            "authority.alpha", 1,
            "thread-" + std::to_string(thread) + "-" + std::to_string(i));
        request.natural_key = "rack-" + std::to_string(thread) + "-" + std::to_string(i);
        if (!fixture.registry->create_domain(request).ok()) {
          ++failures;
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  FFD_CHECK_EQ(failures.load(), 0);
  FFD_CHECK_EQ(fixture.registry->snapshot().domain_count(),
               static_cast<std::size_t>(kThreads * kPerThread));
  FFD_CHECK_EQ(fixture.registry->generation(),
               static_cast<std::uint64_t>(kThreads * kPerThread));
  FFD_CHECK(fixture.registry->publish().ok());
}

FFD_TEST(one_snapshot_is_stable_under_concurrent_reads) {
  Fixture fixture(ffd::Durability::ExplicitPublish);
  const ffd::DomainId first = fixture.create("rack-1");
  const ffd::DomainId second = fixture.create("rack-2");
  ffd::DeclareContainmentRequest containment;
  containment.context = fixture.context();
  containment.parent = first;
  containment.child = second;
  FFD_REQUIRE(fixture.registry->declare_containment(containment).ok());

  const ffd::Snapshot snapshot = fixture.registry->snapshot();
  const std::string reference = snapshot.canonical_text();
  std::atomic<int> mismatches{0};
  std::vector<std::thread> threads;
  for (int thread = 0; thread < 8; ++thread) {
    threads.emplace_back([&] {
      for (int i = 0; i < 25; ++i) {
        if (snapshot.canonical_text() != reference) {
          ++mismatches;
        }
        if (snapshot.domain_count() != 2) {
          ++mismatches;
        }
      }
    });
  }
  // Mutations continue while the readers work: the snapshot must not move.
  for (int i = 0; i < 25; ++i) {
    fixture.create("late-" + std::to_string(i));
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  FFD_CHECK_EQ(mismatches.load(), 0);
  FFD_CHECK_EQ(snapshot.domain_count(), std::size_t{2});
  FFD_CHECK_EQ(fixture.registry->snapshot().domain_count(), std::size_t{27});
}

FFD_TEST(unwritable_destination_and_oversized_files_are_reported) {
  ffdtest::ScratchDir scratch{"adversarial-io"};
  // A file where a directory is required cannot host a store.
  const std::filesystem::path blocker = scratch.file("blocker");
  {
    std::ofstream stream(blocker, std::ios::binary);
    stream << "not a directory";
  }
  ffd::StoreConfig blocked;
  blocked.path = blocker / "store.ffdr";
  ffd::Result<std::unique_ptr<ffd::Registry>> refused = ffd::Registry::open(blocked);
  FFD_REQUIRE(!refused.ok());
  FFD_CHECK(refused.error().code == ffd::ErrorCode::StorageIo ||
            refused.error().code == ffd::ErrorCode::InvalidArgument);

  // A file larger than the configured payload bound is refused before it is read.
  const std::filesystem::path huge = scratch.file("huge.ffdr");
  {
    std::ofstream stream(huge, std::ios::binary);
    const std::string filler(4096, 'x');
    stream << filler;
  }
  ffd::StoreConfig limited;
  limited.path = huge;
  limited.limits.max_payload_bytes = 1024;
  ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(limited);
  FFD_REQUIRE(!snapshot.ok());
  FFD_CHECK(snapshot.error().code == ffd::ErrorCode::LimitExceeded ||
            snapshot.error().code == ffd::ErrorCode::CorruptState);

  // An absurd declared payload length is refused rather than allocated.
  Fixture fixture;
  fixture.create("rack-1");
  FFD_REQUIRE(fixture.registry->publish().ok());
  std::vector<std::uint8_t> bytes;
  FFD_REQUIRE(ffdtest::read_file_bytes(fixture.config.path, bytes));
  FFD_REQUIRE(bytes.size() > 48);
  for (int i = 0; i < 8; ++i) {
    bytes[ffd::detail::kStoreHeaderBytes - 40 + static_cast<std::size_t>(i)] = 0xff;
  }
  FFD_REQUIRE(ffdtest::write_file_bytes(fixture.config.path, bytes));
  ffd::Result<ffd::Snapshot> absurd = ffd::load_snapshot(fixture.config);
  FFD_REQUIRE(!absurd.ok());
  FFD_CHECK(absurd.error().code == ffd::ErrorCode::LimitExceeded ||
            absurd.error().code == ffd::ErrorCode::TruncatedState);
}

FFD_TEST(identity_is_never_reused_after_retirement) {
  Fixture fixture;
  const ffd::DomainId retired = fixture.create("rack-1");
  ffd::RetireDomainRequest retire;
  retire.context = fixture.context();
  retire.domain = retired;
  FFD_REQUIRE(fixture.registry->retire_domain(retire).ok());
  // Recreating the same natural key is refused even though the original is gone
  // from the active model.
  ffd::CreateDomainRequest recreate;
  recreate.context = fixture.context();
  recreate.domain_class = ffd::DomainClass::Rack;
  recreate.natural_key = "rack-1";
  expect_code(fixture.registry->create_domain(recreate), ffd::ErrorCode::DuplicateNaturalKey,
              "natural key reuse after retirement");
  ffd::CreateDomainRequest reuse_identity;
  reuse_identity.context = fixture.context();
  reuse_identity.natural_key = "rack-2";
  reuse_identity.requested_id = retired;
  expect_code(fixture.registry->create_domain(reuse_identity), ffd::ErrorCode::DuplicateIdentity,
              "identity reuse after retirement");
}
