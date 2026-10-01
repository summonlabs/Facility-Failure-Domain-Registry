// Facility Failure Domain Registry - DCCP boundary 49.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>
#include <filesystem>

#include "ffd/types.hpp"

namespace ffd {

// How much of a mutation's effect is durable before the call returns.
enum class Durability : std::uint8_t {
  // Every successful mutation is published as one whole new generation before
  // the call returns (staged write, flush, read-back, digest verify, atomic
  // replace). Durable but pays a full durability cost per mutation.
  DurablePerMutation = 1,
  // Mutations advance only the in-memory generation; publish() commits the
  // current generation. Uncommitted state is discarded on close.
  ExplicitPublish = 2,
};

// Whether mutations must carry an idempotency key.
enum class MutationKeyPolicy : std::uint8_t {
  Required = 1,
  Optional = 2,
};

struct StoreConfig {
  // Store file path. The writer lock file is path + ".lock". Parent directories
  // are created when the store is opened for writing.
  std::filesystem::path path;
  Durability durability{Durability::DurablePerMutation};
  MutationKeyPolicy key_policy{MutationKeyPolicy::Required};
  Limits limits{};
  bool create_if_missing{true};

  // Optional external fencing epoch floor: opening fails with Fenced when the
  // durable epoch is below this value. Used by operators that must not resume
  // from a superseded writer incarnation.
  std::uint64_t writer_epoch_floor{0};
};

// Facts about the opened durable store, useful for diagnostics and tests.
struct StoreInfo {
  bool store_existed{false};
  std::uint64_t writer_epoch{0};
  std::uint64_t durable_generation{0};
  std::uint64_t lockfile_last_generation{0};
  Digest durable_digest{};
};

}  // namespace ffd
