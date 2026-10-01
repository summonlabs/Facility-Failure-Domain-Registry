// Facility Failure Domain Registry - DCCP boundary 49.
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "ffd/snapshot.hpp"
#include "ffd/store.hpp"
#include "ffd/types.hpp"

namespace ffd {

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
struct CreateDomainRequest {
  MutationContext context;
  DomainClass domain_class{DomainClass::Composite};
  std::string natural_key;
  std::string display_name;
  // When set, the exact identity is requested. Requesting an identity that was
  // already issued is refused: identities are never reused.
  std::optional<DomainId> requested_id;
};

struct RetireDomainRequest {
  MutationContext context;
  DomainId domain;
  std::string reason;
};

// Creates a replacement domain and declares that it supersedes the predecessor.
struct SupersedeDomainRequest {
  MutationContext context;
  DomainId predecessor;
  DomainClass domain_class{DomainClass::Composite};
  std::string natural_key;
  std::string display_name;
};

struct AddMembershipRequest {
  MutationContext context;
  DomainId domain;
  ExternalRef resource;
};

// Declares that a domain *is* an external identity owned by another authority.
struct DeclareAliasRequest {
  MutationContext context;
  DomainId domain;
  ExternalRef resource;
};

struct DeclareContainmentRequest {
  MutationContext context;
  DomainId parent;
  DomainId child;
};

// Exactly one of target / external_target must be set.
struct DeclareDependencyRequest {
  MutationContext context;
  DomainId dependent;
  std::optional<DomainId> target;
  std::optional<ExternalRef> external_target;
};

struct DeclareSharedFateRequest {
  MutationContext context;
  DomainId a;
  DomainId b;
};

struct DeclareIndependenceRequest {
  MutationContext context;
  DomainId a;
  DomainId b;
};

struct RevokeClaimRequest {
  MutationContext context;
  ClaimRef claim;
};

struct SetAuthorityPrecedenceRequest {
  MutationContext context;
  AuthorityId authority;
  std::uint32_t precedence{1};
};

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------
struct MutationOutcome {
  std::uint64_t generation{};
  Digest digest{};
  bool replayed{false};   // true when an idempotent replay was resolved
  DomainId domain;        // set by domain-producing mutations
  ClaimRef claim;         // set by claim-producing mutations
  bool claim_valid{false};
};

// ---------------------------------------------------------------------------
// Writer side
// ---------------------------------------------------------------------------
// Owns mutation authority for one store. Construction acquires the exclusive
// OS-level writer lock (a second live process is refused). Registry is not a
// general-purpose thread pool: public entry points serialize on one internal
// mutex that is never held across a call-out, so no reentrancy is possible.
class Registry {
 public:
  // Opens for writing. Fails with WriterLockUnavailable when another live
  // process owns the store, CorruptState/RollbackDetected when durable state is
  // ambiguous, and Fenced when the epoch is below the configured floor.
  [[nodiscard]] static Result<std::unique_ptr<Registry>> open(const StoreConfig& config);

  ~Registry();
  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  [[nodiscard]] Snapshot snapshot() const;
  [[nodiscard]] const StoreConfig& config() const noexcept;
  [[nodiscard]] const StoreInfo& store_info() const noexcept;
  [[nodiscard]] std::uint64_t generation() const;
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::uint64_t writer_epoch() const;

  // Commits the current in-memory generation. With Durability::DurablePerMutation
  // every mutation is already committed; calls with no new state are a no-op.
  [[nodiscard]] Status publish();

  [[nodiscard]] Result<MutationOutcome> create_domain(const CreateDomainRequest& request);
  [[nodiscard]] Result<MutationOutcome> retire_domain(const RetireDomainRequest& request);
  [[nodiscard]] Result<MutationOutcome> supersede_domain(const SupersedeDomainRequest& request);
  [[nodiscard]] Result<MutationOutcome> add_membership(const AddMembershipRequest& request);
  [[nodiscard]] Result<MutationOutcome> declare_alias(const DeclareAliasRequest& request);
  [[nodiscard]] Result<MutationOutcome> declare_containment(const DeclareContainmentRequest& request);
  [[nodiscard]] Result<MutationOutcome> declare_dependency(const DeclareDependencyRequest& request);
  [[nodiscard]] Result<MutationOutcome> declare_shared_fate(const DeclareSharedFateRequest& request);
  [[nodiscard]] Result<MutationOutcome> declare_independence(const DeclareIndependenceRequest& request);
  [[nodiscard]] Result<MutationOutcome> revoke_claim(const RevokeClaimRequest& request);
  [[nodiscard]] Result<MutationOutcome> set_authority_precedence(
      const SetAuthorityPrecedenceRequest& request);

 private:
  struct Impl;
  explicit Registry(std::unique_ptr<Impl> impl);

  std::unique_ptr<Impl> impl_;
};

// Loads the durable generation from a store file without taking the writer lock
// and without creating anything. Intended for read-only downstream consumers.
[[nodiscard]] Result<Snapshot> load_snapshot(const StoreConfig& config);

}  // namespace ffd
