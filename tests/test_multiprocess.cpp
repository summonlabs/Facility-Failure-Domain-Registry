// Facility Failure Domain Registry - real multi-process writer exclusion,
// fencing, abrupt-death recovery and crash-consistency proofs.
//
// Every proof in this file uses independent operating-system processes started
// through CreateProcess, kernel-owned file locks and silent process termination.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "sha256.hpp"
#include "storage.hpp"
#include "support.hpp"
#include "test_framework.hpp"

namespace {

using ffd::DomainId;

struct JournalEntry {
  std::uint64_t generation{0};
  std::string digest;
};

std::vector<JournalEntry> read_journal(const std::filesystem::path& path) {
  std::vector<JournalEntry> entries;
  std::ifstream stream(path);
  std::string line;
  while (std::getline(stream, line)) {
    unsigned long long generation = 0;
    char digest[65] = {0};
    if (std::sscanf(line.c_str(), "GEN %llu %64s", &generation, digest) == 2) {
      entries.push_back(JournalEntry{static_cast<std::uint64_t>(generation), std::string(digest)});
    }
  }
  return entries;
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::string first_token(const std::string& text) {
  const std::size_t end = text.find_first_of(" \r\n");
  return end == std::string::npos ? text : text.substr(0, end);
}

struct ChildFixture {
  ffdtest::ScratchDir scratch{"multiprocess"};
  std::filesystem::path store_path;
  std::filesystem::path out_path;
  std::filesystem::path journal_path;
  std::filesystem::path signal_path;

  ChildFixture() {
    store_path = scratch.file("facility.ffdr");
    out_path = scratch.file("child.out");
    journal_path = scratch.file("commits.log");
    signal_path = scratch.file("signal.flag");
  }

  [[nodiscard]] ffd::StoreConfig config() const {
    ffd::StoreConfig config;
    config.path = store_path;
    config.durability = ffd::Durability::DurablePerMutation;
    return config;
  }

  void reset_outputs() {
    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    std::filesystem::remove(signal_path, ec);
  }
};

// ---------------------------------------------------------------------------
// Writer exclusion across real processes
// ---------------------------------------------------------------------------
FFD_TEST(second_process_writer_is_refused) {
  ChildFixture fixture;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.config());
  FFD_REQUIRE(registry.ok());

  ffdtest::ChildProcess child;
  FFD_REQUIRE(ffdtest::ChildProcess::spawn(
      {"try-writer", fixture.store_path.string(), fixture.out_path.string()}, child));
  FFD_CHECK_EQ(child.wait(), 0);
  const std::string output = first_token(read_text(fixture.out_path));
  FFD_CHECK_EQ(output, std::string("ERROR"));

  // An independent process cannot take mutation authority while this one holds it.
  FFD_CHECK(read_text(fixture.out_path).find("writer_lock_unavailable") != std::string::npos);
}

FFD_TEST(reader_process_observes_the_published_generation) {
  ChildFixture fixture;
  {
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.config());
    FFD_REQUIRE(registry.ok());
    ffd::CreateDomainRequest request;
    request.context = ffdtest::make_context("authority.alpha", 1, "reader-create");
    request.natural_key = "rack-1";
    FFD_REQUIRE(registry.value()->create_domain(request).ok());

    ffdtest::ChildProcess child;
    FFD_REQUIRE(ffdtest::ChildProcess::spawn(
        {"inspect", fixture.store_path.string(), fixture.out_path.string()}, child));
    FFD_CHECK_EQ(child.wait(), 0);
    const std::string output = read_text(fixture.out_path);
    FFD_CHECK(output.find("GEN 1 ") != std::string::npos);
    FFD_CHECK(output.find("DOMAINS 1 ") != std::string::npos);
    FFD_CHECK(output.find(registry.value()->digest().hex()) != std::string::npos);
  }
}

FFD_TEST(abrupt_death_releases_the_kernel_lock_and_fences_the_old_epoch) {
  ChildFixture fixture;
  ffdtest::ChildProcess holder;
  FFD_REQUIRE(ffdtest::ChildProcess::spawn(
      {"hold", fixture.store_path.string(), fixture.out_path.string()}, holder));
  FFD_REQUIRE(ffdtest::wait_for_file(fixture.out_path, holder));
  std::uint64_t child_epoch = 0;
  {
    const std::string output = read_text(fixture.out_path);
    if (output.rfind("READY", 0) != 0) {
      ::ffdtest::report_failure(__FILE__, __LINE__,
                                "holder did not report READY; child said: " + output);
      throw ::ffdtest::AssertionFailure{"holder-ready"};
    }
    child_epoch = std::stoull(output.substr(6));
  }
  FFD_CHECK(child_epoch >= 1);

  // While the child lives, this process is refused.
  ffd::Result<std::unique_ptr<ffd::Registry>> blocked = ffd::Registry::open(fixture.config());
  FFD_REQUIRE(!blocked.ok());
  FFD_CHECK_EQ(blocked.error().code, ffd::ErrorCode::WriterLockUnavailable);

  // Abrupt death is not cooperation: the kernel releases the lock.
  holder.kill();
  FFD_CHECK(!holder.running());
  ffd::Result<std::unique_ptr<ffd::Registry>> successor = ffd::Registry::open(fixture.config());
  FFD_REQUIRE(successor.ok());
  FFD_CHECK(successor.value()->writer_epoch() > child_epoch);
  FFD_CHECK_EQ(successor.value()->generation(), 0u);
}

// ---------------------------------------------------------------------------
// Crash consistency at durable publication boundaries
// ---------------------------------------------------------------------------
void verify_recovered_store(ChildFixture& fixture, const std::vector<JournalEntry>& replayed,
                            std::uint64_t crash_after, const char* what) {
  const std::vector<JournalEntry> journal = read_journal(fixture.journal_path);
  FFD_REQUIRE(journal.size() >= static_cast<std::size_t>(crash_after));
  const std::uint64_t last_generation = journal.back().generation;
  const std::string last_digest = journal.back().digest;

  ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(fixture.config());
  if (!snapshot.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + ": recovery failed: " +
                                  snapshot.error().detail);
    return;
  }
  const std::uint64_t generation = snapshot.value().generation();
  if (generation != last_generation && generation != last_generation + 1) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + ": recovered generation " +
                                  std::to_string(generation) + " is neither " +
                                  std::to_string(last_generation) + " nor " +
                                  std::to_string(last_generation + 1));
    return;
  }
  std::string expected_digest = last_digest;
  if (generation == last_generation + 1) {
    bool found = false;
    for (const JournalEntry& entry : replayed) {
      if (entry.generation == generation) {
        expected_digest = entry.digest;
        found = true;
        break;
      }
    }
    if (!found) {
      ::ffdtest::report_failure(__FILE__, __LINE__,
                                std::string(what) + ": no replay digest for generation " +
                                    std::to_string(generation));
      return;
    }
  }
  if (snapshot.value().digest().hex() != expected_digest) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + ": recovered digest " +
                                  snapshot.value().digest().hex() + " does not match " +
                                  expected_digest);
  }
  // The recovered model must also reopen for writing, with a fresh epoch.
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.config());
  if (!registry.ok()) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              std::string(what) + ": reopen failed: " +
                                  registry.error().detail);
    return;
  }
  FFD_CHECK_EQ(registry.value()->generation(), generation);
}

FFD_TEST(crash_at_every_durable_publication_boundary_recovers) {
  constexpr std::uint64_t kRounds = 4;
  constexpr std::uint64_t kCrashAfter = 6;
  for (std::uint32_t crash_point = 1; crash_point <= 4; ++crash_point) {
    ChildFixture fixture;
    // Replay the same deterministic script in a private store to learn the
    // digest the interrupted process would have produced for its last commit.
    const std::filesystem::path replay_store = fixture.scratch.file("replay.ffdr");
    const std::filesystem::path replay_out = fixture.scratch.file("replay.out");
    ffdtest::ChildProcess replayer;
    FFD_REQUIRE(ffdtest::ChildProcess::spawn({"replay", replay_store.string(), replay_out.string(),
                                              "4242", std::to_string(kRounds)},
                                             replayer));
    FFD_CHECK_EQ(replayer.wait(), 0);
    std::vector<JournalEntry> replayed;
    {
      std::ifstream stream(replay_out);
      std::string line;
      while (std::getline(stream, line)) {
        unsigned long long generation = 0;
        char digest[65] = {0};
        if (std::sscanf(line.c_str(), "GEN %llu %64s", &generation, digest) == 2) {
          replayed.push_back(
              JournalEntry{static_cast<std::uint64_t>(generation), std::string(digest)});
        }
      }
    }
    FFD_REQUIRE(!replayed.empty());

    fixture.reset_outputs();
    ffdtest::ChildProcess writer;
    FFD_REQUIRE(ffdtest::ChildProcess::spawn(
        {"write", fixture.store_path.string(), fixture.out_path.string(), "4242",
         std::to_string(kRounds), fixture.journal_path.string(), std::to_string(kCrashAfter),
         fixture.signal_path.string(), std::to_string(crash_point), std::to_string(kCrashAfter)},
        writer));
    FFD_REQUIRE(ffdtest::wait_for_file(fixture.signal_path, writer));
    const int code = writer.wait();
    FFD_CHECK(code == 3);  // deterministic silent termination, not an ordinary exit

    const std::string what = "crash point " + std::to_string(crash_point);
    verify_recovered_store(fixture, replayed, kCrashAfter, what.c_str());

    // A partial staged file, if any, must not be mistaken for the store.
    for (const auto& entry : std::filesystem::directory_iterator(fixture.scratch.path())) {
      const std::string name = entry.path().filename().string();
      FFD_CHECK(name.find(".tmp-") == std::string::npos);
    }
  }
}

FFD_TEST(external_kill_during_publication_recovers) {
  constexpr std::uint64_t kRounds = 6;
  constexpr std::uint64_t kSignalAfter = 9;
  ChildFixture fixture;
  const std::filesystem::path replay_store = fixture.scratch.file("replay.ffdr");
  const std::filesystem::path replay_out = fixture.scratch.file("replay.out");
  ffdtest::ChildProcess replayer;
  FFD_REQUIRE(ffdtest::ChildProcess::spawn({"replay", replay_store.string(), replay_out.string(),
                                            "777", std::to_string(kRounds)},
                                           replayer));
  FFD_CHECK_EQ(replayer.wait(), 0);
  std::vector<JournalEntry> replayed;
  {
    std::ifstream stream(replay_out);
    std::string line;
    while (std::getline(stream, line)) {
      std::uint64_t generation = 0;
      char digest[65] = {0};
      if (std::sscanf(line.c_str(), "GEN %llu %64s",
                      reinterpret_cast<unsigned long long*>(&generation), digest) == 2) {
        replayed.push_back(JournalEntry{generation, std::string(digest)});
      }
    }
  }
  FFD_REQUIRE(!replayed.empty());

  ffdtest::ChildProcess writer;
  FFD_REQUIRE(ffdtest::ChildProcess::spawn(
      {"write", fixture.store_path.string(), fixture.out_path.string(), "777",
       std::to_string(kRounds), fixture.journal_path.string(), std::to_string(kSignalAfter),
       fixture.signal_path.string(), "0", "0"},
      writer));
  FFD_REQUIRE(ffdtest::wait_for_file(fixture.signal_path, writer));
  writer.kill();

  verify_recovered_store(fixture, replayed, kSignalAfter, "external kill");
}

// ---------------------------------------------------------------------------
// Stale-writer fencing
// ---------------------------------------------------------------------------
FFD_TEST(a_writer_whose_epoch_was_superseded_cannot_publish) {
  ChildFixture fixture;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(fixture.config());
  FFD_REQUIRE(registry.ok());
  ffd::CreateDomainRequest request;
  request.context = ffdtest::make_context("authority.alpha", 1, "fenced-create");
  request.natural_key = "rack-1";
  FFD_REQUIRE(registry.value()->create_domain(request).ok());
  const std::uint64_t generation_before = registry.value()->generation();

  // SYNTHETIC injection: the durable epoch record is advanced behind the live
  // writer's back, exactly as an administrative takeover or a restore would.
  std::filesystem::path lock_path = fixture.store_path;
  lock_path += L".epoch";
  std::vector<std::uint8_t> record;
  FFD_REQUIRE(ffdtest::read_file_bytes(lock_path, record));
  if (record.size() != std::size_t{ffd::detail::kLockRecordBytes}) {
    ::ffdtest::report_failure(__FILE__, __LINE__,
                              "epoch record is " + std::to_string(record.size()) +
                                  " bytes, expected " +
                                  std::to_string(ffd::detail::kLockRecordBytes) + " (" +
                                  lock_path.string() + ")");
    throw ::ffdtest::AssertionFailure{"epoch-record-size"};
  }
  std::uint64_t current_epoch = 0;
  for (int i = 0; i < 8; ++i) {
    current_epoch |= static_cast<std::uint64_t>(record[16 + static_cast<std::size_t>(i)])
                     << (8 * i);
  }
  const std::uint64_t advanced = current_epoch + 5;
  for (int i = 0; i < 8; ++i) {
    record[16 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((advanced >> (8 * i)) & 0xffu);
  }
  const ffd::Digest trailer = ffd::detail::sha256(record.data(), 32);
  for (int i = 0; i < 32; ++i) {
    record[32 + static_cast<std::size_t>(i)] = trailer.bytes[static_cast<std::size_t>(i)];
  }
  FFD_REQUIRE(ffdtest::write_file_bytes(lock_path, record));

  ffd::CreateDomainRequest refused;
  refused.context = ffdtest::make_context("authority.alpha", 1, "fenced-second");
  refused.natural_key = "rack-2";
  const ffd::Result<ffd::MutationOutcome> outcome = registry.value()->create_domain(refused);
  FFD_REQUIRE(!outcome.ok());
  FFD_CHECK_EQ(outcome.error().code, ffd::ErrorCode::Fenced);
  // The refused publication left the durable generation untouched.
  registry.value().reset();
  ffd::Result<std::unique_ptr<ffd::Registry>> successor = ffd::Registry::open(fixture.config());
  FFD_REQUIRE(successor.ok());
  FFD_CHECK_EQ(successor.value()->generation(), generation_before);
}

}  // namespace
