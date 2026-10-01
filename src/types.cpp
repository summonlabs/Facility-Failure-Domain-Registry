// Facility Failure Domain Registry - DCCP boundary 49.
#include <array>
#include <cstdint>
#include <string>

#include "ffd/snapshot.hpp"
#include "ffd/types.hpp"
#include "ffd/version.hpp"

namespace ffd {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

const char* version_string() noexcept { return "1.0.0"; }

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest::hex() const {
  std::string out;
  out.reserve(kDigestBytes * 2);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHexDigits[(byte >> 4u) & 0x0fu]);
    out.push_back(kHexDigits[byte & 0x0fu]);
  }
  return out;
}

std::optional<Digest> Digest::from_hex(std::string_view text) {
  if (text.size() != kDigestBytes * 2) {
    return std::nullopt;
  }
  Digest digest;
  for (std::size_t i = 0; i < kDigestBytes; ++i) {
    const int high = hex_value(text[i * 2]);
    const int low = hex_value(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return std::nullopt;
    }
    digest.bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return digest;
}

const char* to_string(DomainClass value) noexcept {
  switch (value) {
    case DomainClass::PowerSource: return "power_source";
    case DomainClass::PowerDistribution: return "power_distribution";
    case DomainClass::CoolingSource: return "cooling_source";
    case DomainClass::CoolingDistribution: return "cooling_distribution";
    case DomainClass::Room: return "room";
    case DomainClass::Hall: return "hall";
    case DomainClass::Row: return "row";
    case DomainClass::Rack: return "rack";
    case DomainClass::SharedService: return "shared_service";
    case DomainClass::Composite: return "composite";
  }
  return "unknown";
}

std::optional<DomainClass> domain_class_from_string(std::string_view text) noexcept {
  constexpr DomainClass kClasses[] = {
      DomainClass::PowerSource,   DomainClass::PowerDistribution, DomainClass::CoolingSource,
      DomainClass::CoolingDistribution, DomainClass::Room,     DomainClass::Hall,
      DomainClass::Row,           DomainClass::Rack,            DomainClass::SharedService,
      DomainClass::Composite};
  for (const DomainClass candidate : kClasses) {
    const std::string_view name = to_string(candidate);
    if (name == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool is_known_domain_class(std::uint16_t raw) noexcept {
  switch (static_cast<DomainClass>(raw)) {
    case DomainClass::PowerSource:
    case DomainClass::PowerDistribution:
    case DomainClass::CoolingSource:
    case DomainClass::CoolingDistribution:
    case DomainClass::Room:
    case DomainClass::Hall:
    case DomainClass::Row:
    case DomainClass::Rack:
    case DomainClass::SharedService:
    case DomainClass::Composite:
      return true;
  }
  return false;
}

const char* to_string(DomainLifecycle value) noexcept {
  switch (value) {
    case DomainLifecycle::Active: return "active";
    case DomainLifecycle::Retired: return "retired";
    case DomainLifecycle::Superseded: return "superseded";
  }
  return "unknown";
}

const char* to_string(FactKind value) noexcept {
  switch (value) {
    case FactKind::Membership: return "membership";
    case FactKind::Containment: return "containment";
    case FactKind::Dependency: return "dependency";
    case FactKind::SharedFate: return "shared_fate";
    case FactKind::Independence: return "independence";
    case FactKind::Supersession: return "supersession";
    case FactKind::Retirement: return "retirement";
    case FactKind::Retraction: return "retraction";
    case FactKind::ExternalAlias: return "external_alias";
  }
  return "unknown";
}

bool is_known_fact_kind(std::uint16_t raw) noexcept {
  switch (static_cast<FactKind>(raw)) {
    case FactKind::Membership:
    case FactKind::Containment:
    case FactKind::Dependency:
    case FactKind::SharedFate:
    case FactKind::Independence:
    case FactKind::Supersession:
    case FactKind::Retirement:
    case FactKind::Retraction:
    case FactKind::ExternalAlias:
      return true;
  }
  return false;
}

bool is_symmetric_fact_kind(FactKind value) noexcept {
  return value == FactKind::SharedFate || value == FactKind::Independence;
}

bool is_external_fact_kind(FactKind value) noexcept {
  return value == FactKind::Membership || value == FactKind::ExternalAlias;
}

const char* to_string(FactStatus value) noexcept {
  switch (value) {
    case FactStatus::Effective: return "effective";
    case FactStatus::SupersededRevision: return "superseded_revision";
    case FactStatus::Outranked: return "outranked";
    case FactStatus::Conflicting: return "conflicting";
  }
  return "unknown";
}

const char* to_string(ErrorCode value) noexcept {
  switch (value) {
    case ErrorCode::Ok: return "ok";
    case ErrorCode::InvalidArgument: return "invalid_argument";
    case ErrorCode::LimitExceeded: return "limit_exceeded";
    case ErrorCode::DuplicateNaturalKey: return "duplicate_natural_key";
    case ErrorCode::DuplicateIdentity: return "duplicate_identity";
    case ErrorCode::DuplicateClaim: return "duplicate_claim";
    case ErrorCode::UnknownDomain: return "unknown_domain";
    case ErrorCode::UnknownFact: return "unknown_fact";
    case ErrorCode::DomainNotActive: return "domain_not_active";
    case ErrorCode::AlreadyRetired: return "already_retired";
    case ErrorCode::CycleNotAllowed: return "cycle_not_allowed";
    case ErrorCode::SelfReference: return "self_reference";
    case ErrorCode::StaleGeneration: return "stale_generation";
    case ErrorCode::ModelMismatch: return "model_mismatch";
    case ErrorCode::IdempotencyKeyReuse: return "idempotency_key_reuse";
    case ErrorCode::IdempotencyKeyRequired: return "idempotency_key_required";
    case ErrorCode::WriterLockUnavailable: return "writer_lock_unavailable";
    case ErrorCode::Fenced: return "fenced";
    case ErrorCode::RollbackDetected: return "rollback_detected";
    case ErrorCode::CorruptState: return "corrupt_state";
    case ErrorCode::UnsupportedFormatVersion: return "unsupported_format_version";
    case ErrorCode::TruncatedState: return "truncated_state";
    case ErrorCode::DigestMismatch: return "digest_mismatch";
    case ErrorCode::ReadOnly: return "read_only";
    case ErrorCode::StorageIo: return "storage_io";
    case ErrorCode::Overflow: return "overflow";
    case ErrorCode::NotFound: return "not_found";
  }
  return "unknown";
}

const char* error_slug(ErrorCode value) noexcept { return to_string(value); }

const char* to_string(PairVerdict value) noexcept {
  switch (value) {
    case PairVerdict::Unknown: return "unknown";
    case PairVerdict::ProvenSharedFate: return "proven_shared_fate";
    case PairVerdict::ProvenIndependent: return "proven_independent";
    case PairVerdict::Conflicting: return "conflicting";
  }
  return "unknown";
}

const char* to_string(ConflictKind value) noexcept {
  switch (value) {
    case ConflictKind::Claim: return "claim";
    case ConflictKind::Supersession: return "supersession";
    case ConflictKind::AmbiguousAlias: return "ambiguous_alias";
  }
  return "unknown";
}

}  // namespace ffd
