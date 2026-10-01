// Facility Failure Domain Registry - DCCP boundary 49.
#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace ffd::detail {

// Externally influenced quantities are checked; overflow is refused, never
// wrapped.
template <class T>
[[nodiscard]] constexpr std::optional<T> checked_add(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checked arithmetic is defined for unsigned types");
  if (b > static_cast<T>(std::numeric_limits<T>::max() - a)) {
    return std::nullopt;
  }
  return static_cast<T>(a + b);
}

template <class T>
[[nodiscard]] constexpr std::optional<T> checked_sub(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checked arithmetic is defined for unsigned types");
  if (b > a) {
    return std::nullopt;
  }
  return static_cast<T>(a - b);
}

template <class T>
[[nodiscard]] constexpr std::optional<T> checked_mul(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checked arithmetic is defined for unsigned types");
  if (a != 0 && b > static_cast<T>(std::numeric_limits<T>::max() / a)) {
    return std::nullopt;
  }
  return static_cast<T>(a * b);
}

template <class To, class From>
[[nodiscard]] constexpr std::optional<To> checked_cast(From value) noexcept {
  if constexpr (std::is_signed_v<From>) {
    if (value < 0) {
      return std::nullopt;
    }
  }
  const auto converted = static_cast<std::uint64_t>(value);
  if (converted > static_cast<std::uint64_t>(std::numeric_limits<To>::max())) {
    return std::nullopt;
  }
  return static_cast<To>(converted);
}

}  // namespace ffd::detail
