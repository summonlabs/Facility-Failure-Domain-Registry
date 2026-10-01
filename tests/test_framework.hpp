// Facility Failure Domain Registry - test support.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "ffd/snapshot.hpp"
#include "ffd/types.hpp"

namespace ffdtest {

using Body = std::function<void()>;

struct TestCase {
  std::string name;
  Body body;
};

[[nodiscard]] std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* name, Body body);
};

struct AssertionFailure {
  std::string message;
};

void report_failure(const char* file, int line, const std::string& message);

template <class T, class = void>
struct is_streamable : std::false_type {};

template <class T>
struct is_streamable<
    T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

// Rendering used only in failure messages; never part of product behaviour.
template <class T>
[[nodiscard]] std::string to_display(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    using Underlying = std::underlying_type_t<T>;
    if constexpr (std::is_signed_v<Underlying>) {
      return std::to_string(static_cast<long long>(static_cast<Underlying>(value)));
    } else {
      return std::to_string(static_cast<unsigned long long>(static_cast<Underlying>(value)));
    }
  } else if constexpr (is_streamable<T>::value) {
    std::ostringstream out;
    out << value;
    return out.str();
  } else {
    return std::string("<unprintable>");
  }
}

[[nodiscard]] inline std::string to_display(bool value) { return value ? "true" : "false"; }

[[nodiscard]] inline std::string to_display(const std::string& value) {
  return "\"" + value + "\"";
}

[[nodiscard]] inline std::string to_display(const char* value) {
  return std::string("\"") + (value == nullptr ? "" : value) + "\"";
}

[[nodiscard]] inline std::string to_display(ffd::DomainId value) {
  return "#" + std::to_string(value.value);
}

[[nodiscard]] inline std::string to_display(ffd::DomainClass value) {
  return ffd::to_string(value);
}

[[nodiscard]] inline std::string to_display(ffd::DomainLifecycle value) {
  return ffd::to_string(value);
}

[[nodiscard]] inline std::string to_display(ffd::FactKind value) { return ffd::to_string(value); }

[[nodiscard]] inline std::string to_display(ffd::FactStatus value) { return ffd::to_string(value); }

[[nodiscard]] inline std::string to_display(ffd::ErrorCode value) { return ffd::to_string(value); }

[[nodiscard]] inline std::string to_display(ffd::PairVerdict value) { return ffd::to_string(value); }

[[nodiscard]] inline std::string to_display(const ffd::Digest& value) { return value.hex(); }

// Runs every registered test (or those whose name starts with argv[1]).
// Test commands are run plainly: no timeouts, no watchdogs, no forced kills.
int run_all(int argc, char** argv);

}  // namespace ffdtest

#define FFD_TEST(name)                                                 \
  static void name();                                                  \
  static const ::ffdtest::Registrar ffd_registrar_##name(#name, name); \
  static void name()

#define FFD_CHECK(condition)                                                    \
  do {                                                                          \
    if (!(condition)) {                                                         \
      ::ffdtest::report_failure(__FILE__, __LINE__, "check failed: " #condition); \
    }                                                                           \
  } while (false)

#define FFD_CHECK_EQ(lhs, rhs)                                                        \
  do {                                                                                \
    const auto& ffd_lhs = (lhs);                                                      \
    const auto& ffd_rhs = (rhs);                                                      \
    if (!(ffd_lhs == ffd_rhs)) {                                                      \
      ::ffdtest::report_failure(                                                      \
          __FILE__, __LINE__,                                                         \
          std::string("expected " #lhs " == " #rhs " but got ") +                     \
              ::ffdtest::to_display(ffd_lhs) + " vs " + ::ffdtest::to_display(ffd_rhs)); \
    }                                                                                 \
  } while (false)

#define FFD_REQUIRE(condition)                                      \
  do {                                                              \
    if (!(condition)) {                                             \
      ::ffdtest::report_failure(__FILE__, __LINE__,                 \
                                "requirement failed: " #condition); \
      throw ::ffdtest::AssertionFailure{#condition};                \
    }                                                               \
  } while (false)
