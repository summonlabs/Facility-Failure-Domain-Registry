// Facility Failure Domain Registry - durable store tests.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "storage.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;

struct StoreFixture {
  ffdtest::ScratchDir scratch{"storage"};
  std::filesystem::path store_path;
  std::uint64_t counter{0};

  explicit StoreFixture(ffd::Durability durability = ffd::Durability::DurablePerMutation,
                        std::uint64_t max_domains = 200000) {
    store_path = scratch.file("facility.ffdr");
    config.durability = durability;
    config.limits.max_domains = max_domains;
  }

  ffd::StoreConfig config;

  [[nodiscard]] ffd::StoreConfig make_config() const {
    ffd::StoreConfig copy = config;
    copy.path = store_path;
    return copy;
  }

  [[nodiscard]] std::unique_ptr<ffd::Registry> open() {
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(make_config());
    if (!registry.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "open failed: " + registry.error().detail);
      throw ::ffdtest::AssertionFailure{"open"};
    }
    return std::move(registry.value());
  }

  DomainId create(ffd::Registry& registry, const std::string& key) {
    ffd::CreateDomainRequest request;
    request.context = ffdtest::make_context("authority.alpha", 1,
                                            ffdtest::index_key("k", ++counter));
    request.domain_class = ffd::DomainClass::Rack;
    request.natural_key = key;
    ffd::Result<ffd::MutationOutcome> outcome = registry.create_domain(request);
    if (!outcome.ok()) {
      ::ffdtest::report_failure(__FILE__, __LINE__, "create failed: " + outcome.error().detail);
      throw ::ffdtest::AssertionFailure{"create"};
    }
    return outcome.value().domain;
  }

  [[nodiscard]] std::filesystem::path lock_path() const {
    std::filesystem::path path = store_path;
    path += L".lock";
    return path;
  }

  [[nodiscard]] std::filesystem::path epoch_path() const {
    std::filesystem::path path = store_path;
    path += L".epoch";
    return path;
  }
};

[[nodiscard]] ffd::ErrorCode load_code(const std::filesystem::path& path) {
  ffd::StoreConfig config;
  config.path = path;
  ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(config);
  if (snapshot.ok()) {
    return ffd::ErrorCode::Ok;
  }
  return snapshot.error().code;
}

}  // namespace

FFD_TEST(durable_round_trip_across_handles) {
  StoreFixture fixture;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    const DomainId first = fixture.create(*registry, "rack-1");
    const DomainId second = fixture.create(*registry, "rack-2");
    ffd::DeclareContainmentRequest containment;
    containment.context = ffdtest::make_context("authority.alpha", 1, "c-1");
    containment.parent = first;
    containment.child = second;
    FFD_REQUIRE(registry->declare_containment(containment).ok());
    FFD_CHECK_EQ(registry->generation(), 3u);
  }
  const std::uint64_t expected_generation = 3;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    FFD_CHECK_EQ(registry->generation(), expected_generation);
    const ffd::Snapshot snapshot = registry->snapshot();
    FFD_CHECK_EQ(snapshot.domain_count(), std::size_t{2});
    FFD_CHECK_EQ(snapshot.fact_count(), std::size_t{1});
    FFD_CHECK(registry->store_info().store_existed);
  }
  // A read-only consumer sees the same generation and digest.
  ffd::Result<ffd::Snapshot> loaded = ffd::load_snapshot(fixture.make_config());
  FFD_REQUIRE(loaded.ok());
  FFD_CHECK_EQ(loaded.value().generation(), expected_generation);
  ffd::Result<ffd::Snapshot> reopened = ffd::load_snapshot(fixture.make_config());
  FFD_REQUIRE(reopened.ok());
  FFD_CHECK(loaded.value().digest() == reopened.value().digest());
}

FFD_TEST(reader_does_not_need_the_writer_lock) {
  StoreFixture fixture;
  std::unique_ptr<ffd::Registry> registry = fixture.open();
  fixture.create(*registry, "rack-1");
  // The writer lock is held by this process; a read-only load still succeeds.
  ffd::Result<ffd::Snapshot> loaded = ffd::load_snapshot(fixture.make_config());
  FFD_REQUIRE(loaded.ok());
  FFD_CHECK_EQ(loaded.value().generation(), 1u);
  // A second writer in the same process is refused by the kernel lock.
  ffd::Result<std::unique_ptr<ffd::Registry>> second = ffd::Registry::open(fixture.make_config());
  FFD_REQUIRE(!second.ok());
  FFD_CHECK_EQ(second.error().code, ffd::ErrorCode::WriterLockUnavailable);
}

FFD_TEST(missing_store_is_not_found) {
  ffdtest::ScratchDir scratch{"storage-missing"};
  ffd::StoreConfig config;
  config.path = scratch.file("absent.ffdr");
  ffd::Result<ffd::Snapshot> loaded = ffd::load_snapshot(config);
  FFD_REQUIRE(!loaded.ok());
  FFD_CHECK_EQ(loaded.error().code, ffd::ErrorCode::NotFound);
}

FFD_TEST(store_file_appears_only_after_the_first_mutation) {
  StoreFixture fixture;
  std::unique_ptr<ffd::Registry> registry = fixture.open();
  FFD_CHECK(!std::filesystem::exists(fixture.store_path));
  FFD_CHECK(std::filesystem::exists(fixture.lock_path()));
  FFD_CHECK(std::filesystem::exists(fixture.epoch_path()));
  fixture.create(*registry, "rack-1");
  FFD_CHECK(std::filesystem::exists(fixture.store_path));
}

FFD_TEST(single_byte_corruption_is_always_detected) {
  StoreFixture fixture;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    for (int i = 0; i < 8; ++i) {
      fixture.create(*registry, "rack-" + std::to_string(i));
    }
  }
  std::vector<std::uint8_t> pristine;
  FFD_REQUIRE(ffdtest::read_file_bytes(fixture.store_path, pristine));
  FFD_REQUIRE(pristine.size() > 200);

  std::size_t detected = 0;
  for (std::size_t offset = 0; offset < pristine.size(); ++offset) {
    std::vector<std::uint8_t> damaged = pristine;
    damaged[offset] = static_cast<std::uint8_t>(damaged[offset] ^ 0x5au);
    FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, damaged));
    const ffd::ErrorCode code = load_code(fixture.store_path);
    if (code == ffd::ErrorCode::Ok) {
      ::ffdtest::report_failure(__FILE__, __LINE__,
                                "corruption at offset " + std::to_string(offset) +
                                    " was accepted");
    } else {
      ++detected;
    }
  }
  FFD_CHECK_EQ(detected, pristine.size());

  // Specific classes of damage produce specific refusals.
  {
    std::vector<std::uint8_t> damaged = pristine;
    damaged[0] = static_cast<std::uint8_t>(damaged[0] ^ 0xffu);
    FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, damaged));
    FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::CorruptState);
  }
  {
    std::vector<std::uint8_t> damaged = pristine;
    damaged[8] = 99;  // format version
    FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, damaged));
    FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::UnsupportedFormatVersion);
  }
  {
    std::vector<std::uint8_t> damaged = pristine;
    damaged[16] = static_cast<std::uint8_t>(damaged[16] + 1u);  // generation
    FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, damaged));
    FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::DigestMismatch);
  }
}

FFD_TEST(every_truncation_is_detected) {
  StoreFixture fixture;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-1");
    fixture.create(*registry, "rack-2");
  }
  std::vector<std::uint8_t> pristine;
  FFD_REQUIRE(ffdtest::read_file_bytes(fixture.store_path, pristine));
  for (std::size_t length = 0; length < pristine.size(); ++length) {
    const std::vector<std::uint8_t> truncated(pristine.begin(),
                                              pristine.begin() + static_cast<std::ptrdiff_t>(length));
    FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, truncated));
    const ffd::ErrorCode code = load_code(fixture.store_path);
    if (code == ffd::ErrorCode::Ok) {
      ::ffdtest::report_failure(__FILE__, __LINE__,
                                "truncation to " + std::to_string(length) + " bytes was accepted");
    }
  }
  // Trailing junk is refused as well.
  std::vector<std::uint8_t> extended = pristine;
  extended.push_back(0x00);
  FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, extended));
  FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::TruncatedState);
}

FFD_TEST(rollback_to_an_earlier_generation_is_refused) {
  StoreFixture fixture;
  std::vector<std::uint8_t> older;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-1");
    FFD_REQUIRE(ffdtest::read_file_bytes(fixture.store_path, older));
    fixture.create(*registry, "rack-2");
    fixture.create(*registry, "rack-3");
  }
  // Replacing the published generation with an older, internally valid file is
  // exactly the rollback an operator or a restore could perform by accident.
  FFD_REQUIRE(ffdtest::write_file_bytes(fixture.store_path, older));
  FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::RollbackDetected);

  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.make_config());
  FFD_REQUIRE(!registry.ok());
  FFD_CHECK_EQ(registry.error().code, ffd::ErrorCode::RollbackDetected);

  // Losing the file entirely while the epoch record remembers a generation is a
  // rollback too.
  std::error_code ec;
  std::filesystem::remove(fixture.store_path, ec);
  FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::NotFound);
  ffd::Result<std::unique_ptr<ffd::Registry>> missing =
      ffd::Registry::open(fixture.make_config());
  FFD_REQUIRE(!missing.ok());
  FFD_CHECK_EQ(missing.error().code, ffd::ErrorCode::RollbackDetected);
}

FFD_TEST(epoch_record_corruption_is_refused) {
  StoreFixture fixture;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-1");
  }
  std::vector<std::uint8_t> record;
  FFD_REQUIRE(ffdtest::read_file_bytes(fixture.epoch_path(), record));
  FFD_CHECK_EQ(record.size(), std::size_t{ffd::detail::kLockRecordBytes});
  record[record.size() - 1] = static_cast<std::uint8_t>(record.back() ^ 0xffu);
  FFD_REQUIRE(ffdtest::write_file_bytes(fixture.epoch_path(), record));
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.make_config());
  FFD_REQUIRE(!registry.ok());
  FFD_CHECK_EQ(registry.error().code, ffd::ErrorCode::CorruptState);

  // A truncated epoch record is ambiguous state, not a fresh store.
  const std::vector<std::uint8_t> partial(record.begin(), record.begin() + 12);
  FFD_REQUIRE(ffdtest::write_file_bytes(fixture.epoch_path(), partial));
  ffd::Result<std::unique_ptr<ffd::Registry>> second = ffd::Registry::open(fixture.make_config());
  FFD_REQUIRE(!second.ok());
  FFD_CHECK_EQ(second.error().code, ffd::ErrorCode::CorruptState);
}

FFD_TEST(stale_staged_files_are_removed_on_open) {
  StoreFixture fixture;
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-1");
  }
  std::filesystem::path stale = fixture.store_path;
  stale += L".tmp-12345-0";
  {
    std::ofstream stream(stale, std::ios::binary);
    stream << "partial";
  }
  FFD_CHECK(std::filesystem::exists(stale));
  std::unique_ptr<ffd::Registry> registry = fixture.open();
  FFD_CHECK(!std::filesystem::exists(stale));
  FFD_CHECK_EQ(registry->generation(), 1u);
}

FFD_TEST(explicit_publish_defers_durability) {
  StoreFixture fixture(ffd::Durability::ExplicitPublish);
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-1");
    fixture.create(*registry, "rack-2");
    FFD_CHECK_EQ(registry->generation(), 2u);
    // Nothing is durable yet: there is no file to load.
    FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::NotFound);
    FFD_CHECK(registry->publish().ok());
    FFD_CHECK(registry->publish().ok());  // idempotent when already committed
  }
  FFD_CHECK_EQ(load_code(fixture.store_path), ffd::ErrorCode::Ok);

  // Uncommitted work is discarded on close, never half-written.
  {
    std::unique_ptr<ffd::Registry> registry = fixture.open();
    fixture.create(*registry, "rack-3");
    FFD_CHECK_EQ(registry->generation(), 3u);
  }
  ffd::Result<ffd::Snapshot> loaded = ffd::load_snapshot(fixture.make_config());
  FFD_REQUIRE(loaded.ok());
  FFD_CHECK_EQ(loaded.value().generation(), 2u);
  FFD_CHECK_EQ(loaded.value().domain_count(), std::size_t{2});
}

FFD_TEST(configured_limits_are_enforced) {
  StoreFixture fixture(ffd::Durability::DurablePerMutation, 3);
  std::unique_ptr<ffd::Registry> registry = fixture.open();
  fixture.create(*registry, "rack-1");
  fixture.create(*registry, "rack-2");
  fixture.create(*registry, "rack-3");
  ffd::CreateDomainRequest request;
  request.context = ffdtest::make_context("authority.alpha", 1, "overflow-create");
  request.natural_key = "rack-4";
  ffd::Result<ffd::MutationOutcome> outcome = registry->create_domain(request);
  FFD_REQUIRE(!outcome.ok());
  FFD_CHECK_EQ(outcome.error().code, ffd::ErrorCode::LimitExceeded);
  FFD_CHECK_EQ(registry->generation(), 3u);

  // A payload limit that cannot hold the model refuses publication instead of
  // writing a truncated generation.
  StoreFixture tiny(ffd::Durability::DurablePerMutation);
  tiny.config.limits.max_payload_bytes = 1024;
  std::unique_ptr<ffd::Registry> small = tiny.open();
  const std::string long_key(180, 'k');
  ffd::CreateDomainRequest big;
  big.context = ffdtest::make_context("authority.alpha", 1, "big-create");
  big.natural_key = long_key;
  FFD_CHECK(small->create_domain(big).ok());
  bool refused = false;
  for (int i = 0; i < 200 && !refused; ++i) {
    ffd::CreateDomainRequest more;
    more.context = ffdtest::make_context("authority.alpha", 1,
                                         ffdtest::index_key("more", static_cast<std::uint64_t>(i)));
    more.natural_key = long_key + "-" + std::to_string(i);
    ffd::Result<ffd::MutationOutcome> result = small->create_domain(more);
    if (!result.ok()) {
      refused = true;
      FFD_CHECK_EQ(result.error().code, ffd::ErrorCode::LimitExceeded);
    }
  }
  FFD_CHECK(refused);
}

FFD_TEST(device_names_and_long_paths_are_ordinary_files) {
  ffdtest::ScratchDir scratch{"storage-paths"};
  // A reserved device name is only a device when it reaches the Win32 layer
  // unqualified; the store must treat it as a plain file name.
  ffd::StoreConfig device_config;
  device_config.path = scratch.file("CON");
  ffd::Result<std::unique_ptr<ffd::Registry>> device = ffd::Registry::open(device_config);
  FFD_REQUIRE(device.ok());
  ffd::CreateDomainRequest request;
  request.context = ffdtest::make_context("authority.alpha", 1, "device-create");
  request.natural_key = "rack-1";
  FFD_CHECK(device.value()->create_domain(request).ok());
  device.value().reset();

  // Deeply nested stores work through extended-length paths.
  std::filesystem::path deep = scratch.path();
  for (int level = 0; level < 8; ++level) {
    deep /= "level-" + std::to_string(level) + "-0123456789012345678901234567890123456789";
  }
  ffd::StoreConfig deep_config;
  deep_config.path = deep / "facility.ffdr";
  ffd::Result<std::unique_ptr<ffd::Registry>> nested = ffd::Registry::open(deep_config);
  if (!nested.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              "deep store open failed: " + nested.error().detail + " path=" +
                                  deep_config.path.string());
  }
  FFD_REQUIRE(nested.ok());
  request.natural_key = "rack-deep";
  FFD_CHECK(nested.value()->create_domain(request).ok());
  nested.value().reset();
  FFD_CHECK_EQ(load_code(deep_config.path), ffd::ErrorCode::Ok);

  // A relative path with parent segments is normalised, not rejected.
  ffd::StoreConfig relative;
  relative.path = scratch.path() / "sub" / ".." / "relative.ffdr";
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(relative);
  FFD_REQUIRE(registry.ok());
  request.natural_key = "rack-relative";
  FFD_CHECK(registry.value()->create_domain(request).ok());
  registry.value().reset();
  FFD_CHECK(std::filesystem::exists(scratch.file("relative.ffdr")));
  FFD_CHECK(!std::filesystem::exists(scratch.file("sub")));
}
