// Facility Failure Domain Registry - DCCP boundary 49.
#include "validate.hpp"

#include <cstdint>

#include "checked.hpp"

namespace ffd::detail {
namespace {

[[nodiscard]] bool is_ascii_authority_char(unsigned char c) noexcept {
  const bool digit = c >= '0' && c <= '9';
  const bool upper = c >= 'A' && c <= 'Z';
  const bool lower = c >= 'a' && c <= 'z';
  const bool punctuation = c == '.' || c == '_' || c == '-' || c == ':' || c == '/';
  return digit || upper || lower || punctuation;
}

[[nodiscard]] bool is_control(unsigned char c) noexcept {
  return c < 0x20u || c == 0x7fu;
}

[[nodiscard]] Status make_error(ErrorCode code, std::string detail) {
  return Status(Error{code, std::move(detail)});
}

}  // namespace

bool is_valid_utf8(std::string_view text) noexcept {
  const auto* data = reinterpret_cast<const unsigned char*>(text.data());
  std::size_t index = 0;
  const std::size_t size = text.size();
  while (index < size) {
    const unsigned char lead = data[index];
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    if (lead < 0x80u) {
      ++index;
      continue;
    }
    if ((lead & 0xe0u) == 0xc0u) {
      extra = 1;
      code_point = static_cast<std::uint32_t>(lead & 0x1fu);
    } else if ((lead & 0xf0u) == 0xe0u) {
      extra = 2;
      code_point = static_cast<std::uint32_t>(lead & 0x0fu);
    } else if ((lead & 0xf8u) == 0xf0u) {
      extra = 3;
      code_point = static_cast<std::uint32_t>(lead & 0x07u);
    } else {
      return false;
    }
    if (index + extra >= size) {
      return false;
    }
    for (std::size_t i = 1; i <= extra; ++i) {
      const unsigned char continuation = data[index + i];
      if ((continuation & 0xc0u) != 0x80u) {
        return false;
      }
      code_point = (code_point << 6u) | static_cast<std::uint32_t>(continuation & 0x3fu);
    }
    // Reject overlong encodings, surrogates and out-of-range code points.
    if (extra == 1 && code_point < 0x80u) {
      return false;
    }
    if (extra == 2 && code_point < 0x800u) {
      return false;
    }
    if (extra == 3 && code_point < 0x10000u) {
      return false;
    }
    if (code_point > 0x10ffffu) {
      return false;
    }
    if (code_point >= 0xd800u && code_point <= 0xdfffu) {
      return false;
    }
    index += extra + 1;
  }
  return true;
}

Status validate_authority(const AuthorityId& authority, const Limits& limits) {
  if (authority.empty()) {
    return make_error(ErrorCode::InvalidArgument, "authority id must not be empty");
  }
  if (authority.value.size() > limits.max_string_bytes) {
    return make_error(ErrorCode::LimitExceeded, "authority id exceeds the configured limit");
  }
  for (const char raw : authority.value) {
    const auto c = static_cast<unsigned char>(raw);
    if (!is_ascii_authority_char(c)) {
      return make_error(ErrorCode::InvalidArgument,
                        "authority id must use [A-Za-z0-9._:-/] only");
    }
  }
  return Status{};
}

Status validate_resource_id(const ResourceId& resource, const Limits& limits) {
  if (resource.empty()) {
    return make_error(ErrorCode::InvalidArgument, "resource id must not be empty");
  }
  if (resource.value.size() > limits.max_string_bytes) {
    return make_error(ErrorCode::LimitExceeded, "resource id exceeds the configured limit");
  }
  if (!is_valid_utf8(resource.value)) {
    return make_error(ErrorCode::InvalidArgument, "resource id is not valid UTF-8");
  }
  for (const char raw : resource.value) {
    if (is_control(static_cast<unsigned char>(raw))) {
      return make_error(ErrorCode::InvalidArgument, "resource id contains a control character");
    }
  }
  return Status{};
}

Status validate_external_ref(const ExternalRef& ref, const Limits& limits) {
  const Status authority_status = validate_authority(ref.authority, limits);
  if (!authority_status.ok()) {
    return authority_status;
  }
  return validate_resource_id(ref.resource, limits);
}

Status validate_natural_key(std::string_view key, const Limits& limits) {
  if (key.empty()) {
    return make_error(ErrorCode::InvalidArgument, "natural key must not be empty");
  }
  if (key.size() > limits.max_natural_key_bytes) {
    return make_error(ErrorCode::LimitExceeded, "natural key exceeds the configured limit");
  }
  if (!is_valid_utf8(key)) {
    return make_error(ErrorCode::InvalidArgument, "natural key is not valid UTF-8");
  }
  for (const char raw : key) {
    if (is_control(static_cast<unsigned char>(raw))) {
      return make_error(ErrorCode::InvalidArgument, "natural key contains a control character");
    }
  }
  const bool space_like_front = key.front() == ' ' || key.front() == '\t';
  const bool space_like_back = key.back() == ' ' || key.back() == '\t';
  if (space_like_front || space_like_back) {
    return make_error(ErrorCode::InvalidArgument,
                      "natural key must not start or end with whitespace");
  }
  return Status{};
}

Status validate_display_name(std::string_view name, const Limits& limits) {
  if (name.empty()) {
    return Status{};
  }
  if (name.size() > limits.max_display_name_bytes) {
    return make_error(ErrorCode::LimitExceeded, "display name exceeds the configured limit");
  }
  if (!is_valid_utf8(name)) {
    return make_error(ErrorCode::InvalidArgument, "display name is not valid UTF-8");
  }
  for (const char raw : name) {
    if (is_control(static_cast<unsigned char>(raw))) {
      return make_error(ErrorCode::InvalidArgument, "display name contains a control character");
    }
  }
  return Status{};
}

Status validate_evidence(std::string_view evidence, const Limits& limits) {
  if (evidence.empty()) {
    return Status{};
  }
  if (evidence.size() > limits.max_evidence_bytes) {
    return make_error(ErrorCode::LimitExceeded, "evidence text exceeds the configured limit");
  }
  if (!is_valid_utf8(evidence)) {
    return make_error(ErrorCode::InvalidArgument, "evidence text is not valid UTF-8");
  }
  for (const char raw : evidence) {
    const auto c = static_cast<unsigned char>(raw);
    if (is_control(c) && c != '\t' && c != '\n') {
      return make_error(ErrorCode::InvalidArgument, "evidence text contains a control character");
    }
  }
  return Status{};
}

Status validate_provenance(const Provenance& provenance, const Limits& limits) {
  const Status authority_status = validate_authority(provenance.authority, limits);
  if (!authority_status.ok()) {
    return authority_status;
  }
  return validate_evidence(provenance.evidence, limits);
}

Status validate_idempotency_key(const IdempotencyKey& key, const Limits& limits) {
  const Status authority_status = validate_authority(key.authority, limits);
  if (!authority_status.ok()) {
    return authority_status;
  }
  if (key.value.empty()) {
    return make_error(ErrorCode::InvalidArgument, "idempotency key value must not be empty");
  }
  if (key.value.size() > limits.max_string_bytes) {
    return make_error(ErrorCode::LimitExceeded, "idempotency key exceeds the configured limit");
  }
  for (const char raw : key.value) {
    const auto c = static_cast<unsigned char>(raw);
    if (!is_ascii_authority_char(c)) {
      return make_error(ErrorCode::InvalidArgument,
                        "idempotency key must use [A-Za-z0-9._:-/] only");
    }
  }
  return Status{};
}

Status validate_domain_id(DomainId id, std::string_view what) {
  if (!id.valid()) {
    return make_error(ErrorCode::InvalidArgument, std::string(what) + " must be a valid domain id");
  }
  return Status{};
}

Status validate_limits(const Limits& limits) {
  if (limits.max_domains == 0 || limits.max_facts == 0) {
    return make_error(ErrorCode::InvalidArgument, "limits must allow at least one domain and fact");
  }
  if (limits.max_string_bytes == 0 || limits.max_natural_key_bytes == 0) {
    return make_error(ErrorCode::InvalidArgument, "string limits must be positive");
  }
  if (limits.max_natural_key_bytes > limits.max_string_bytes ||
      limits.max_display_name_bytes > limits.max_string_bytes ||
      limits.max_evidence_bytes > limits.max_string_bytes) {
    return make_error(ErrorCode::InvalidArgument, "field limits must not exceed max_string_bytes");
  }
  if (limits.max_payload_bytes < 1024) {
    return make_error(ErrorCode::InvalidArgument, "max_payload_bytes is implausibly small");
  }
  if (limits.max_idempotency_entries == 0) {
    return make_error(ErrorCode::InvalidArgument, "max_idempotency_entries must be positive");
  }
  return Status{};
}

std::string sanitize_for_detail(std::string_view text, std::size_t max_bytes) {
  std::string out;
  out.reserve(text.size() < max_bytes ? text.size() : max_bytes);
  std::size_t taken = 0;
  for (const char raw : text) {
    if (taken >= max_bytes) {
      out += "...";
      break;
    }
    const auto c = static_cast<unsigned char>(raw);
    if (c == '\n' || c == '\r' || c == '\t') {
      out.push_back(' ');
    } else if (is_control(c)) {
      out.push_back('?');
    } else {
      out.push_back(raw);
    }
    ++taken;
  }
  return out;
}

}  // namespace ffd::detail
