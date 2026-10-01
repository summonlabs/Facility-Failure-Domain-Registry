// Facility Failure Domain Registry - DCCP boundary 49.
#include "canonical.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "checked.hpp"
#include "sha256.hpp"
#include "validate.hpp"
#include "ffd/version.hpp"

namespace ffd::detail {
namespace {

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
}

[[nodiscard]] Status decode_error(ErrorCode code, std::string detail) {
  return Status(Error{code, std::move(detail)});
}

[[nodiscard]] bool is_membership_like(FactKind kind) noexcept {
  return kind == FactKind::Membership || kind == FactKind::ExternalAlias;
}

}  // namespace

// ---------------------------------------------------------------------------
// ByteWriter
// ---------------------------------------------------------------------------
void ByteWriter::u8(std::uint8_t value) { bytes_.push_back(value); }

void ByteWriter::u16(std::uint16_t value) {
  bytes_.push_back(static_cast<std::uint8_t>(value & 0xffu));
  bytes_.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
}

void ByteWriter::u32(std::uint32_t value) { append_u32_le(bytes_, value); }

void ByteWriter::u64(std::uint64_t value) {
  append_u32_le(bytes_, static_cast<std::uint32_t>(value & 0xffffffffull));
  append_u32_le(bytes_, static_cast<std::uint32_t>((value >> 32u) & 0xffffffffull));
}

void ByteWriter::raw(const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  bytes_.insert(bytes_.end(), bytes, bytes + size);
}

void ByteWriter::str(std::string_view text) {
  u32(static_cast<std::uint32_t>(text.size()));
  raw(text.data(), text.size());
}

void ByteWriter::digest(const Digest& value) { raw(value.bytes.data(), value.bytes.size()); }

// ---------------------------------------------------------------------------
// ByteReader
// ---------------------------------------------------------------------------
bool ByteReader::u8(std::uint8_t& value) noexcept {
  if (remaining() < 1) {
    return false;
  }
  value = data_[position_];
  ++position_;
  return true;
}

bool ByteReader::u16(std::uint16_t& value) noexcept {
  if (remaining() < 2) {
    return false;
  }
  value = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[position_]) |
                                     (static_cast<std::uint16_t>(data_[position_ + 1]) << 8u));
  position_ += 2;
  return true;
}

bool ByteReader::u32(std::uint32_t& value) noexcept {
  if (remaining() < 4) {
    return false;
  }
  value = static_cast<std::uint32_t>(data_[position_]) |
          (static_cast<std::uint32_t>(data_[position_ + 1]) << 8u) |
          (static_cast<std::uint32_t>(data_[position_ + 2]) << 16u) |
          (static_cast<std::uint32_t>(data_[position_ + 3]) << 24u);
  position_ += 4;
  return true;
}

bool ByteReader::u64(std::uint64_t& value) noexcept {
  std::uint32_t low = 0;
  std::uint32_t high = 0;
  if (!u32(low) || !u32(high)) {
    return false;
  }
  value = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32u);
  return true;
}

bool ByteReader::raw(void* destination, std::size_t size) noexcept {
  if (remaining() < size) {
    return false;
  }
  if (destination != nullptr) {
    std::memcpy(destination, data_ + position_, size);
  }
  position_ += size;
  return true;
}

bool ByteReader::skip(std::size_t count) noexcept {
  if (remaining() < count) {
    return false;
  }
  position_ += count;
  return true;
}

bool ByteReader::str(std::string& value, std::uint64_t max_bytes) {
  std::uint32_t length = 0;
  if (!u32(length)) {
    return false;
  }
  if (static_cast<std::uint64_t>(length) > max_bytes) {
    return false;
  }
  if (remaining() < length) {
    return false;
  }
  value.assign(reinterpret_cast<const char*>(data_ + position_), length);
  position_ += length;
  return true;
}

bool ByteReader::digest(Digest& value) noexcept {
  return raw(value.bytes.data(), value.bytes.size());
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> encode_model_content(const ModelState& state) {
  ByteWriter writer;
  writer.u32(kCanonicalPayloadVersion);
  writer.u64(state.identity_high_water);

  writer.u32(static_cast<std::uint32_t>(state.domains.size()));
  for (const auto& [id, record] : state.domains) {
    writer.u64(id.value);
    writer.u16(static_cast<std::uint16_t>(record.domain_class));
    writer.str(record.natural_key);
    writer.str(record.display_name);
  }

  writer.u32(static_cast<std::uint32_t>(state.precedence.size()));
  for (const auto& [authority, precedence] : state.precedence) {
    writer.str(authority.value);
    writer.u32(precedence);
  }

  const std::vector<const FactRecord*> facts = canonical_fact_pointers(state);
  writer.u32(static_cast<std::uint32_t>(facts.size()));
  for (const FactRecord* fact : facts) {
    writer.u16(static_cast<std::uint16_t>(fact->kind));
    writer.u64(fact->subject.value);
    writer.u64(fact->object.value);
    writer.u8(fact->external_target ? 1u : 0u);
    if (fact->external_target) {
      writer.str(fact->external.authority.value);
      writer.str(fact->external.resource.value);
    }
    const bool retraction = fact->kind == FactKind::Retraction;
    writer.u8(retraction ? 1u : 0u);
    if (retraction) {
      writer.u16(static_cast<std::uint16_t>(fact->target_kind));
      writer.str(fact->target_authority.value);
    }
    writer.u64(fact->provenance.authority_revision);
    writer.str(fact->provenance.evidence);
    writer.str(fact->provenance.authority.value);
  }
  return writer.take();
}

std::vector<std::uint8_t> encode_durable_state(const ModelState& state) {
  const std::vector<std::uint8_t> content = encode_model_content(state);
  ByteWriter writer;
  writer.u32(kCanonicalPayloadVersion);
  writer.u32(static_cast<std::uint32_t>(content.size()));
  writer.raw(content.data(), content.size());

  writer.u32(static_cast<std::uint32_t>(state.journal.size()));
  for (const auto& [key, stored] : state.journal) {
    const JournalEntry& entry = stored;
    (void)key;
    writer.str(entry.key.authority.value);
    writer.str(entry.key.value);
    writer.digest(entry.request_fingerprint);
    writer.u64(entry.generation_after);
    writer.digest(entry.digest_after);
    writer.u64(entry.result_domain.value);
    writer.u8(entry.result_claim_valid ? 1u : 0u);
    if (entry.result_claim_valid) {
      writer.u16(static_cast<std::uint16_t>(entry.result_claim.kind));
      writer.u64(entry.result_claim.subject.value);
      writer.u64(entry.result_claim.object.value);
      const bool external = is_external_fact_kind(entry.result_claim.kind);
      writer.u8(external ? 1u : 0u);
      if (external) {
        writer.str(entry.result_claim.external.authority.value);
        writer.str(entry.result_claim.external.resource.value);
      }
      const bool retraction = entry.result_claim.kind == FactKind::Retraction;
      writer.u8(retraction ? 1u : 0u);
      if (retraction) {
        writer.u16(static_cast<std::uint16_t>(entry.result_claim.target_kind));
        writer.str(entry.result_claim.target_authority.value);
      }
    }
    writer.u64(entry.sequence);
  }
  writer.u64(state.journal_sequence);
  return writer.take();
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------
namespace {

Status decode_claim(ByteReader& reader, const Limits& limits, ClaimRef& claim) {
  std::uint16_t raw_kind = 0;
  std::uint64_t subject = 0;
  std::uint64_t object = 0;
  std::uint8_t external_flag = 0;
  if (!reader.u16(raw_kind) || !reader.u64(subject) || !reader.u64(object) ||
      !reader.u8(external_flag)) {
    return decode_error(ErrorCode::TruncatedState, "claim reference is truncated");
  }
  if (!is_known_fact_kind(raw_kind) || external_flag > 1) {
    return decode_error(ErrorCode::CorruptState, "claim reference is malformed");
  }
  claim.kind = static_cast<FactKind>(raw_kind);
  claim.subject = DomainId{subject};
  claim.object = DomainId{object};
  const bool external = external_flag == 1;
  if (external != is_external_fact_kind(claim.kind)) {
    return decode_error(ErrorCode::CorruptState, "claim reference external marker mismatch");
  }
  if (external) {
    if (!reader.str(claim.external.authority.value, limits.max_string_bytes) ||
        !reader.str(claim.external.resource.value, limits.max_string_bytes)) {
      return decode_error(ErrorCode::CorruptState, "claim reference external id is malformed");
    }
  }
  std::uint8_t retraction_flag = 0;
  if (!reader.u8(retraction_flag) || retraction_flag > 1) {
    return decode_error(ErrorCode::CorruptState, "claim reference retraction marker is malformed");
  }
  const bool retraction = retraction_flag == 1;
  if (retraction != (claim.kind == FactKind::Retraction)) {
    return decode_error(ErrorCode::CorruptState, "claim reference retraction marker mismatch");
  }
  if (retraction) {
    std::uint16_t raw_target_kind = 0;
    if (!reader.u16(raw_target_kind) || !is_known_fact_kind(raw_target_kind) ||
        raw_target_kind == static_cast<std::uint16_t>(FactKind::Retraction)) {
      return decode_error(ErrorCode::CorruptState, "claim reference target kind is invalid");
    }
    claim.target_kind = static_cast<FactKind>(raw_target_kind);
    if (!reader.str(claim.target_authority.value, limits.max_string_bytes)) {
      return decode_error(ErrorCode::CorruptState, "claim reference target authority is malformed");
    }
    if (external != is_external_fact_kind(claim.target_kind)) {
      return decode_error(ErrorCode::CorruptState,
                          "claim reference external marker does not match target kind");
    }
  } else {
    claim.target_kind = claim.kind;
  }
  return Status{};
}

Status decode_model_content(const std::uint8_t* data, std::size_t size, const Limits& limits,
                            ModelState& state) {
  ByteReader reader(data, size);
  std::uint32_t version = 0;
  if (!reader.u32(version)) {
    return decode_error(ErrorCode::TruncatedState, "content section is truncated");
  }
  if (version != kCanonicalPayloadVersion) {
    return decode_error(ErrorCode::UnsupportedFormatVersion, "unsupported content version");
  }
  if (!reader.u64(state.identity_high_water)) {
    return decode_error(ErrorCode::TruncatedState, "content section is truncated");
  }

  std::uint32_t domain_count = 0;
  if (!reader.u32(domain_count)) {
    return decode_error(ErrorCode::TruncatedState, "content section is truncated");
  }
  if (static_cast<std::uint64_t>(domain_count) > limits.max_domains) {
    return decode_error(ErrorCode::LimitExceeded, "domain count exceeds the configured limit");
  }
  DomainId previous_domain;
  for (std::uint32_t i = 0; i < domain_count; ++i) {
    DomainRecord record;
    std::uint64_t raw_id = 0;
    std::uint16_t raw_class = 0;
    if (!reader.u64(raw_id) || !reader.u16(raw_class)) {
      return decode_error(ErrorCode::TruncatedState, "domain record is truncated");
    }
    if (raw_id == 0) {
      return decode_error(ErrorCode::CorruptState, "domain identity 0 is not assignable");
    }
    record.id = DomainId{raw_id};
    if (previous_domain.valid() && !(previous_domain < record.id)) {
      return decode_error(ErrorCode::CorruptState, "domain records are not strictly ordered");
    }
    previous_domain = record.id;
    if (!is_known_domain_class(raw_class)) {
      return decode_error(ErrorCode::CorruptState, "unknown domain class");
    }
    record.domain_class = static_cast<DomainClass>(raw_class);
    if (!reader.str(record.natural_key, limits.max_natural_key_bytes) ||
        !reader.str(record.display_name, limits.max_display_name_bytes)) {
      return decode_error(ErrorCode::CorruptState, "domain string is invalid or oversized");
    }
    if (!validate_natural_key(record.natural_key, limits).ok()) {
      return decode_error(ErrorCode::CorruptState, "domain natural key is invalid");
    }
    if (!validate_display_name(record.display_name, limits).ok()) {
      return decode_error(ErrorCode::CorruptState, "domain display name is invalid");
    }
    state.domains.emplace(record.id, std::move(record));
  }

  std::uint32_t precedence_count = 0;
  if (!reader.u32(precedence_count)) {
    return decode_error(ErrorCode::TruncatedState, "content section is truncated");
  }
  if (static_cast<std::uint64_t>(precedence_count) > limits.max_domains) {
    return decode_error(ErrorCode::LimitExceeded, "precedence table exceeds the configured limit");
  }
  for (std::uint32_t i = 0; i < precedence_count; ++i) {
    AuthorityId authority;
    std::uint32_t precedence = 0;
    if (!reader.str(authority.value, limits.max_string_bytes) || !reader.u32(precedence)) {
      return decode_error(ErrorCode::TruncatedState, "precedence record is truncated");
    }
    if (authority.empty() || !validate_authority(authority, limits).ok()) {
      return decode_error(ErrorCode::CorruptState, "precedence authority is invalid");
    }
    if (!state.precedence.emplace(std::move(authority), precedence).second) {
      return decode_error(ErrorCode::CorruptState, "duplicate precedence entry");
    }
  }

  std::uint32_t fact_count = 0;
  if (!reader.u32(fact_count)) {
    return decode_error(ErrorCode::TruncatedState, "content section is truncated");
  }
  if (static_cast<std::uint64_t>(fact_count) > limits.max_facts) {
    return decode_error(ErrorCode::LimitExceeded, "fact count exceeds the configured limit");
  }
  for (std::uint32_t i = 0; i < fact_count; ++i) {
    FactRecord fact;
    std::uint16_t raw_kind = 0;
    std::uint64_t subject = 0;
    std::uint64_t object = 0;
    std::uint8_t external_flag = 0;
    if (!reader.u16(raw_kind) || !reader.u64(subject) || !reader.u64(object) ||
        !reader.u8(external_flag)) {
      return decode_error(ErrorCode::TruncatedState, "fact record is truncated");
    }
    if (!is_known_fact_kind(raw_kind) || external_flag > 1) {
      return decode_error(ErrorCode::CorruptState, "fact record is malformed");
    }
    fact.kind = static_cast<FactKind>(raw_kind);
    fact.target_kind = fact.kind;
    fact.subject = DomainId{subject};
    fact.object = DomainId{object};
    fact.external_target = external_flag == 1;
    const bool external = fact.external_target;
    if (fact.kind != FactKind::Retraction && external != is_external_fact_kind(fact.kind)) {
      return decode_error(ErrorCode::CorruptState, "external marker does not match the fact kind");
    }
    if (external) {
      if (!reader.str(fact.external.authority.value, limits.max_string_bytes) ||
          !reader.str(fact.external.resource.value, limits.max_string_bytes)) {
        return decode_error(ErrorCode::CorruptState, "external reference is invalid or oversized");
      }
      if (!validate_external_ref(fact.external, limits).ok()) {
        return decode_error(ErrorCode::CorruptState, "external reference is invalid");
      }
    }
    std::uint8_t retraction_flag = 0;
    if (!reader.u8(retraction_flag) || retraction_flag > 1) {
      return decode_error(ErrorCode::CorruptState, "invalid retraction marker");
    }
    const bool retraction = retraction_flag == 1;
    if (retraction != (fact.kind == FactKind::Retraction)) {
      return decode_error(ErrorCode::CorruptState, "retraction marker does not match the fact kind");
    }
    if (retraction) {
      std::uint16_t raw_target_kind = 0;
      if (!reader.u16(raw_target_kind) || !is_known_fact_kind(raw_target_kind) ||
          raw_target_kind == static_cast<std::uint16_t>(FactKind::Retraction)) {
        return decode_error(ErrorCode::CorruptState, "retraction target kind is invalid");
      }
      fact.target_kind = static_cast<FactKind>(raw_target_kind);
      if (!reader.str(fact.target_authority.value, limits.max_string_bytes)) {
        return decode_error(ErrorCode::TruncatedState, "retraction target authority is truncated");
      }
      if (!validate_authority(fact.target_authority, limits).ok()) {
        return decode_error(ErrorCode::CorruptState, "retraction target authority is invalid");
      }
      if (fact.external_target != is_external_fact_kind(fact.target_kind)) {
        return decode_error(ErrorCode::CorruptState,
                            "retraction external marker does not match the target kind");
      }
    }
    if (!reader.u64(fact.provenance.authority_revision) ||
        !reader.str(fact.provenance.evidence, limits.max_evidence_bytes) ||
        !reader.str(fact.provenance.authority.value, limits.max_string_bytes)) {
      return decode_error(ErrorCode::TruncatedState, "fact provenance is truncated");
    }
    if (!validate_provenance(fact.provenance, limits).ok()) {
      return decode_error(ErrorCode::CorruptState, "fact provenance is invalid");
    }
    if (!fact.subject.valid()) {
      return decode_error(ErrorCode::CorruptState, "fact subject is not a valid identity");
    }
    const FactKind slot_kind = fact.kind == FactKind::Retraction ? fact.target_kind : fact.kind;
    if (is_membership_like(slot_kind) && (fact.object.valid() || !external)) {
      return decode_error(ErrorCode::CorruptState, "membership record carries an invalid object");
    }
    if (slot_kind == FactKind::Retirement && (fact.object.valid() || external)) {
      return decode_error(ErrorCode::CorruptState, "retirement record carries a target object");
    }
    if (slot_kind == FactKind::Dependency && !external && !fact.object.valid()) {
      return decode_error(ErrorCode::CorruptState, "dependency target is not a valid identity");
    }
    if ((slot_kind == FactKind::Containment || slot_kind == FactKind::SharedFate ||
         slot_kind == FactKind::Independence || slot_kind == FactKind::Supersession) &&
        !fact.object.valid()) {
      return decode_error(ErrorCode::CorruptState, "fact object is not a valid identity");
    }
    if (slot_kind == FactKind::Supersession && fact.object == fact.subject) {
      return decode_error(ErrorCode::CorruptState, "self supersession is not representable");
    }
    if (is_symmetric_fact_kind(slot_kind) && fact.object < fact.subject) {
      return decode_error(ErrorCode::CorruptState, "symmetric fact is not in canonical order");
    }
    state.facts.push_back(std::move(fact));
  }

  const std::vector<const FactRecord*> ordered = canonical_fact_pointers(state);
  if (ordered.size() != state.facts.size()) {
    return decode_error(ErrorCode::CorruptState, "fact section is inconsistent");
  }
  for (std::size_t i = 1; i < ordered.size(); ++i) {
    if (!canonical_fact_less(*ordered[i - 1], *ordered[i])) {
      return decode_error(ErrorCode::CorruptState, "fact records are not strictly ordered");
    }
  }
  if (!reader.at_end()) {
    return decode_error(ErrorCode::CorruptState, "content section has trailing bytes");
  }
  return Status{};
}

}  // namespace

Status decode_durable_state(const std::uint8_t* data, std::size_t size, const Limits& limits,
                            ModelState& out) {
  if (data == nullptr && size != 0) {
    return decode_error(ErrorCode::InvalidArgument, "null payload buffer");
  }
  ByteReader reader(data, size);
  std::uint32_t version = 0;
  std::uint32_t content_size = 0;
  if (!reader.u32(version) || !reader.u32(content_size)) {
    return decode_error(ErrorCode::TruncatedState, "payload header is truncated");
  }
  if (version != kCanonicalPayloadVersion) {
    return decode_error(ErrorCode::UnsupportedFormatVersion, "unsupported payload version");
  }
  if (static_cast<std::uint64_t>(content_size) > reader.remaining()) {
    return decode_error(ErrorCode::TruncatedState, "declared content length exceeds the payload");
  }

  const std::size_t content_start = reader.position();
  ModelState state;
  const Status content_status =
      decode_model_content(data + content_start, content_size, limits, state);
  if (!content_status.ok()) {
    return content_status;
  }
  if (!reader.skip(content_size)) {
    return decode_error(ErrorCode::TruncatedState, "payload is truncated");
  }

  std::uint32_t journal_count = 0;
  if (!reader.u32(journal_count)) {
    return decode_error(ErrorCode::TruncatedState, "journal section is truncated");
  }
  if (static_cast<std::uint64_t>(journal_count) > limits.max_idempotency_entries) {
    return decode_error(ErrorCode::LimitExceeded, "journal exceeds the configured limit");
  }
  std::uint64_t previous_sequence = 0;
  for (std::uint32_t i = 0; i < journal_count; ++i) {
    JournalEntry entry;
    if (!reader.str(entry.key.authority.value, limits.max_string_bytes) ||
        !reader.str(entry.key.value, limits.max_string_bytes)) {
      return decode_error(ErrorCode::TruncatedState, "journal key is truncated");
    }
    if (!validate_idempotency_key(entry.key, limits).ok()) {
      return decode_error(ErrorCode::CorruptState, "journal key is invalid");
    }
    if (!reader.digest(entry.request_fingerprint) || !reader.u64(entry.generation_after) ||
        !reader.digest(entry.digest_after)) {
      return decode_error(ErrorCode::TruncatedState, "journal record is truncated");
    }
    std::uint64_t result_domain = 0;
    std::uint8_t has_claim = 0;
    if (!reader.u64(result_domain) || !reader.u8(has_claim) || has_claim > 1) {
      return decode_error(ErrorCode::TruncatedState, "journal record is truncated");
    }
    entry.result_domain = DomainId{result_domain};
    entry.result_claim_valid = has_claim == 1;
    if (entry.result_claim_valid) {
      const Status claim_status = decode_claim(reader, limits, entry.result_claim);
      if (!claim_status.ok()) {
        return claim_status;
      }
    }
    if (!reader.u64(entry.sequence) || entry.sequence == 0) {
      return decode_error(ErrorCode::CorruptState, "journal sequence is malformed");
    }
    previous_sequence = std::max(previous_sequence, entry.sequence);
    if (entry.generation_after == 0) {
      return decode_error(ErrorCode::CorruptState, "journal generation is malformed");
    }
    if (!state.journal.emplace(entry.key, std::move(entry)).second) {
      return decode_error(ErrorCode::CorruptState, "journal contains a duplicate key");
    }
  }
  if (!reader.u64(state.journal_sequence)) {
    return decode_error(ErrorCode::TruncatedState, "journal sequence counter is truncated");
  }
  if (!reader.at_end()) {
    return decode_error(ErrorCode::CorruptState, "payload has trailing bytes");
  }
  std::uint64_t highest_sequence = 0;
  for (const auto& [key, entry] : state.journal) {
    (void)key;
    highest_sequence = std::max(highest_sequence, entry.sequence);
  }
  if (state.journal_sequence < highest_sequence) {
    return decode_error(ErrorCode::CorruptState, "journal sequence counter is behind the journal");
  }

  out = std::move(state);
  return Status{};
}

Digest digest_of(const std::vector<std::uint8_t>& bytes) noexcept {
  return sha256(bytes.data(), bytes.size());
}

}  // namespace ffd::detail
