// Facility Failure Domain Registry - DCCP boundary 49.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>

#ifndef FFD_VERSION_MAJOR
#define FFD_VERSION_MAJOR 1
#endif
#ifndef FFD_VERSION_MINOR
#define FFD_VERSION_MINOR 0
#endif
#ifndef FFD_VERSION_PATCH
#define FFD_VERSION_PATCH 0
#endif

namespace ffd {

inline constexpr std::uint32_t kVersionMajor = FFD_VERSION_MAJOR;
inline constexpr std::uint32_t kVersionMinor = FFD_VERSION_MINOR;
inline constexpr std::uint32_t kVersionPatch = FFD_VERSION_PATCH;

// Version of the durable store format this build reads and writes.
inline constexpr std::uint32_t kFormatVersion = 1;

// Version of the canonical serialization used for content digests.
inline constexpr std::uint32_t kCanonicalPayloadVersion = 1;

// Identifier of the DCCP boundary implemented by this library.
inline constexpr std::uint32_t kDccpBoundary = 49;

// "1.0.0"
const char* version_string() noexcept;

}  // namespace ffd
