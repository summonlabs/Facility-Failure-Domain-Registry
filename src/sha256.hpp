// Facility Failure Domain Registry - DCCP boundary 49.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ffd/types.hpp"

namespace ffd::detail {

// FIPS 180-4 SHA-256.
class Sha256 {
 public:
  Sha256() noexcept;

  void update(const void* data, std::size_t size) noexcept;
  void update(std::string_view text) noexcept;
  [[nodiscard]] Digest finish() noexcept;

 private:
  void process_block(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8];
  std::uint64_t total_bytes_;
  std::uint8_t buffer_[64];
  std::size_t buffer_size_;
};

[[nodiscard]] Digest sha256(const void* data, std::size_t size) noexcept;
[[nodiscard]] Digest sha256(std::string_view text) noexcept;

}  // namespace ffd::detail
