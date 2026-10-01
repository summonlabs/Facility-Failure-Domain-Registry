// Facility Failure Domain Registry - test support.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "ffd/registry.hpp"

namespace ffdtest {

// Per-test scratch directory under the process temporary directory. Removed on
// destruction unless FFD_KEEP_SCRATCH is set, so the host is left clean.
class ScratchDir {
 public:
  explicit ScratchDir(const std::string& label);
  ~ScratchDir();
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
  [[nodiscard]] std::filesystem::path file(const std::string& name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
  bool keep_{false};
};

// Deterministic xorshift64* generator: every randomized test prints its seed and
// can be reproduced exactly.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) noexcept;

  [[nodiscard]] std::uint64_t next() noexcept;
  [[nodiscard]] std::uint32_t below(std::uint32_t bound) noexcept;
  [[nodiscard]] bool chance(std::uint32_t numerator, std::uint32_t denominator) noexcept;
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t state_;
  std::uint64_t seed_;
};

[[nodiscard]] ffd::MutationContext make_context(const char* authority, std::uint64_t revision,
                                                const std::string& key_value,
                                                std::uint64_t expected_generation = 0);

[[nodiscard]] ffd::MutationContext make_context_without_key(const char* authority,
                                                            std::uint64_t revision);

[[nodiscard]] std::string index_key(const char* prefix, std::uint64_t counter);

[[nodiscard]] ffd::AuthorityId authority(const char* value);
[[nodiscard]] ffd::ExternalRef external(const char* owner, const std::string& resource);

// Reads a whole file as bytes; used to corrupt or truncate durable stores.
[[nodiscard]] bool read_file_bytes(const std::filesystem::path& path,
                                   std::vector<std::uint8_t>& out);
[[nodiscard]] bool write_file_bytes(const std::filesystem::path& path,
                                    const std::vector<std::uint8_t>& bytes);

// Real independent OS process used by the multiprocess and crash proofs.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  // Starts the helper executable with the given arguments. Returns false when
  // the helper cannot be located or started.
  [[nodiscard]] static bool spawn(const std::vector<std::string>& arguments,
                                  ChildProcess& out);

  [[nodiscard]] bool running() const;
  // Waits without any timeout and returns the exit code, or -1 when unavailable.
  [[nodiscard]] int wait();
  // Silent, deterministic termination (no dialog, no dump, no unwinding).
  void kill();
  [[nodiscard]] std::uint64_t process_id() const noexcept { return pid_; }
  [[nodiscard]] bool valid() const noexcept { return process_ != nullptr; }

 private:
  void release();

  void* process_{nullptr};
  void* thread_{nullptr};
  std::uint64_t pid_{0};
};

// Absolute path of the helper executable: taken from FFD_TEST_CHILD_PATH when
// the harness provides it, otherwise from the directory of the running binary.
[[nodiscard]] std::filesystem::path child_executable_path();

// Waits until the named file appears, failing when the child exits first. No
// timeout is involved: the wait ends on the observable condition.
[[nodiscard]] bool wait_for_file(const std::filesystem::path& path, const ChildProcess& child);

// Deterministic multi-mutation script shared by the crash and recovery proofs.
// Performs rounds of domain creation, membership, nesting, shared fate and
// independence declarations, invoking the observer after every commit.
using CommitObserver = std::function<void(std::uint64_t, const ffd::Digest&)>;
void apply_script(ffd::Registry& registry, std::uint64_t seed, std::uint64_t rounds,
                  const CommitObserver& on_commit);

// Number of mutations performed by apply_script for a given number of rounds.
[[nodiscard]] std::uint64_t script_mutations(std::uint64_t rounds);

}  // namespace ffdtest
