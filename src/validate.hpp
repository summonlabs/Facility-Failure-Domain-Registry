// Facility Failure Domain Registry - DCCP boundary 49.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "ffd/types.hpp"

namespace ffd::detail {

// Structural validation of externally supplied identities and text. These
// checks are deterministic and independent of model state.
[[nodiscard]] bool is_valid_utf8(std::string_view text) noexcept;

[[nodiscard]] Status validate_authority(const AuthorityId& authority, const Limits& limits);
[[nodiscard]] Status validate_resource_id(const ResourceId& resource, const Limits& limits);
[[nodiscard]] Status validate_external_ref(const ExternalRef& ref, const Limits& limits);
[[nodiscard]] Status validate_natural_key(std::string_view key, const Limits& limits);
[[nodiscard]] Status validate_display_name(std::string_view name, const Limits& limits);
[[nodiscard]] Status validate_evidence(std::string_view evidence, const Limits& limits);
[[nodiscard]] Status validate_provenance(const Provenance& provenance, const Limits& limits);
[[nodiscard]] Status validate_idempotency_key(const IdempotencyKey& key, const Limits& limits);
[[nodiscard]] Status validate_domain_id(DomainId id, std::string_view what);
[[nodiscard]] Status validate_limits(const Limits& limits);

// Truncates and sanitizes text for inclusion in an Error::detail string.
[[nodiscard]] std::string sanitize_for_detail(std::string_view text, std::size_t max_bytes = 96);

}  // namespace ffd::detail
