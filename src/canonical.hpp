// Facility Failure Domain Registry - DCCP boundary 49.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ffd/types.hpp"
#include "model.hpp"

namespace ffd::detail {

// Little-endian, length-prefixed, strictly bounded writer. Canonical output
// never depends on container iteration order or thread timing.
class ByteWriter {
 public:
  void u8(std::uint8_t value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void raw(const void* data, std::size_t size);
  void str(std::string_view text);
  void digest(const Digest& value);

  [[nodiscard]] const std::vector<std::uint8_t>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(bytes_); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }

 private:
  std::vector<std::uint8_t> bytes_;
};

class ByteReader {
 public:
  ByteReader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

  [[nodiscard]] bool u8(std::uint8_t& value) noexcept;
  [[nodiscard]] bool u16(std::uint16_t& value) noexcept;
  [[nodiscard]] bool u32(std::uint32_t& value) noexcept;
  [[nodiscard]] bool u64(std::uint64_t& value) noexcept;
  [[nodiscard]] bool raw(void* destination, std::size_t size) noexcept;
  [[nodiscard]] bool str(std::string& value, std::uint64_t max_bytes);
  [[nodiscard]] bool digest(Digest& value) noexcept;
  [[nodiscard]] bool skip(std::size_t count) noexcept;

  [[nodiscard]] bool at_end() const noexcept { return position_ == size_; }
  [[nodiscard]] std::size_t position() const noexcept { return position_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return size_ - position_; }

 private:
  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t position_{0};
};

// Canonical encoding of the model content. The digest is taken over exactly
// these bytes, so two models with the same declarations have the same digest
// regardless of insertion order.
[[nodiscard]] std::vector<std::uint8_t> encode_model_content(const ModelState& state);
// Canonical encoding of the whole durable state: content plus the idempotency
// journal. This is the durable payload of a published generation.
[[nodiscard]] std::vector<std::uint8_t> encode_durable_state(const ModelState& state);
[[nodiscard]] Status decode_durable_state(const std::uint8_t* data, std::size_t size,
                                          const Limits& limits, ModelState& out);

[[nodiscard]] Digest digest_of(const std::vector<std::uint8_t>& bytes) noexcept;

}  // namespace ffd::detail