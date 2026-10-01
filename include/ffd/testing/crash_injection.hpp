// Facility Failure Domain Registry - test support.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Deterministic durable-publication crash injection. This header is not
// installed and is not part of the public product surface. The injection points
// are only compiled into the library when FFD_ENABLE_CRASH_INJECTION is defined;
// otherwise every function here is an inert no-op.
#pragma once

#include <cstdint>

namespace ffd::testing {

enum class CrashPoint : std::uint32_t {
  None = 0,
  // Terminate part-way through writing the staged file, leaving a partial temp
  // artifact behind.
  DuringTempWrite = 1,
  // Terminate after the staged file is written and flushed, before the atomic
  // replace.
  AfterTempWrite = 2,
  // Terminate immediately after the atomic replace, before the epoch record is
  // updated.
  AfterPublishBeforeEpoch = 3,
  // Terminate after the atomic replace and the epoch record update.
  AfterPublish = 4,
};

void set_crash_point(CrashPoint point) noexcept;
[[nodiscard]] CrashPoint crash_point() noexcept;
[[nodiscard]] bool crash_injection_enabled() noexcept;

// Called by the storage layer at the named boundary.
void reach_crash_point(CrashPoint point) noexcept;

}  // namespace ffd::testing
