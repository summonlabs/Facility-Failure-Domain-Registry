// Facility Failure Domain Registry - DCCP boundary 49.
//
// Durable store: one versioned, integrity-checked, atomically published file
// plus a kernel-locked epoch record that fences stale writers.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

#include "ffd/store.hpp"
#include "ffd/types.hpp"
#include "model.hpp"

namespace ffd::detail {

// Durable layout.
//
//   <store>          magic[8] | format u32 | header bytes u32 | generation u64
//                    | writer epoch u64 | payload length u64 | content digest[32]
//                    | payload | SHA-256 trailer[32]
//   <store>.epoch    magic[8] | format u32 | record bytes u32 | epoch u64
//                    | last generation u64 | SHA-256 trailer[32]
//   <store>.lock     empty; the kernel-owned exclusive lock lives here, so the
//                    epoch record stays readable and auditable while a writer
//                    owns the store.
inline constexpr std::uint64_t kStoreHeaderBytes = 72;
inline constexpr std::uint64_t kStoreTrailerBytes = 32;
inline constexpr std::uint64_t kLockRecordBytes = 64;

struct DurableSection {
  ModelState state;
  std::uint64_t generation{0};
  std::uint64_t writer_epoch{0};
  Digest model_digest;
};

// Owns the OS-level writer lock for one store path.
class StoreFile {
 public:
  StoreFile() = default;
  ~StoreFile();
  StoreFile(const StoreFile&) = delete;
  StoreFile& operator=(const StoreFile&) = delete;

  // Acquires exclusive mutation authority, validates durable state and opens the
  // store for writing. Failure leaves no lock held.
  [[nodiscard]] static Result<std::unique_ptr<StoreFile>> open_writer(const StoreConfig& config,
                                                                     StoreInfo& info,
                                                                     DurableSection& section);

  // Strictly decodes a store file without taking the writer lock.
  [[nodiscard]] static Result<DurableSection> read_file(const std::filesystem::path& path,
                                                        const Limits& limits);

  // Publishes one whole generation: staged write, flush, read-back verify,
  // atomic replace, epoch update.
  [[nodiscard]] Status publish(const ModelState& state, std::uint64_t generation,
                               const Digest& model_digest);

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
  [[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }
  [[nodiscard]] std::uint64_t durable_generation() const noexcept { return durable_generation_; }

 private:
  std::filesystem::path path_;
  void* lock_handle_{nullptr};
  std::uint64_t epoch_{0};
  std::uint64_t durable_generation_{0};
  std::uint64_t temp_counter_{0};
  Limits limits_{};
};

// Read-only rollback comparison against the durable epoch record. Performs the
// comparison only when a consistent view is available.
[[nodiscard]] std::uint64_t epoch_high_water(const std::filesystem::path& store_path,
                                             bool* consistent);

[[nodiscard]] std::filesystem::path lock_path_for(const std::filesystem::path& store_path);
[[nodiscard]] std::filesystem::path epoch_path_for(const std::filesystem::path& store_path);

}  // namespace ffd::detail
