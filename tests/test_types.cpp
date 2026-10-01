// Facility Failure Domain Registry - unit tests for types and primitives.
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

#include "checked.hpp"
#include "ffd/snapshot.hpp"
#include "ffd/types.hpp"
#include "ffd/version.hpp"
#include "sha256.hpp"
#include "test_framework.hpp"
#include "validate.hpp"

namespace {

ffd::Digest digest_of_text(const std::string& text) {
  return ffd::detail::sha256(text.data(), text.size());
}

}  // namespace

FFD_TEST(version_and_boundary_constants) {
  FFD_CHECK_EQ(std::string(ffd::version_string()), std::string("1.0.0"));
  FFD_CHECK_EQ(ffd::kVersionMajor, 1u);
  FFD_CHECK_EQ(ffd::kDccpBoundary, 49u);
  FFD_CHECK_EQ(ffd::kFormatVersion, 1u);
}

FFD_TEST(sha256_known_vectors) {
  FFD_CHECK_EQ(digest_of_text("").hex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  FFD_CHECK_EQ(digest_of_text("abc").hex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  FFD_CHECK_EQ(
      digest_of_text("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  const std::string million(1000000, 'a');
  FFD_CHECK_EQ(digest_of_text(million).hex(),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
  for (const std::size_t size : {std::size_t{55}, std::size_t{56}, std::size_t{57},
                                 std::size_t{63}, std::size_t{64}, std::size_t{65}}) {
    const std::string text(size, 'x');
    ffd::detail::Sha256 streamed;
    for (std::size_t i = 0; i < text.size(); ++i) {
      streamed.update(text.data() + i, 1);
    }
    FFD_CHECK_EQ(streamed.finish().hex(), digest_of_text(text).hex());
  }
}

FFD_TEST(digest_hex_round_trip) {
  const ffd::Digest digest = digest_of_text("facility");
  const std::string text = digest.hex();
  FFD_CHECK_EQ(text.size(), std::size_t{64});
  const std::optional<ffd::Digest> parsed = ffd::Digest::from_hex(text);
  FFD_REQUIRE(parsed.has_value());
  FFD_CHECK(parsed.value() == digest);
  FFD_CHECK(!ffd::Digest::from_hex("").has_value());
  FFD_CHECK(!ffd::Digest::from_hex(std::string(63, 'a')).has_value());
  FFD_CHECK(!ffd::Digest::from_hex(std::string(64, 'z')).has_value());
  FFD_CHECK(ffd::Digest{}.is_zero());
  FFD_CHECK(!digest.is_zero());
}

FFD_TEST(domain_class_names_round_trip) {
  const ffd::DomainClass classes[] = {
      ffd::DomainClass::PowerSource,   ffd::DomainClass::PowerDistribution,
      ffd::DomainClass::CoolingSource, ffd::DomainClass::CoolingDistribution,
      ffd::DomainClass::Room,          ffd::DomainClass::Hall,
      ffd::DomainClass::Row,           ffd::DomainClass::Rack,
      ffd::DomainClass::SharedService, ffd::DomainClass::Composite};
  for (const ffd::DomainClass value : classes) {
    const std::optional<ffd::DomainClass> parsed =
        ffd::domain_class_from_string(ffd::to_string(value));
    FFD_REQUIRE(parsed.has_value());
    FFD_CHECK(parsed.value() == value);
  }
  FFD_CHECK(!ffd::domain_class_from_string("not-a-class").has_value());
  FFD_CHECK(!ffd::is_known_domain_class(0));
  FFD_CHECK(!ffd::is_known_domain_class(11));
  FFD_CHECK(ffd::is_known_domain_class(1));
}

FFD_TEST(fact_kind_properties) {
  FFD_CHECK(ffd::is_symmetric_fact_kind(ffd::FactKind::SharedFate));
  FFD_CHECK(ffd::is_symmetric_fact_kind(ffd::FactKind::Independence));
  FFD_CHECK(!ffd::is_symmetric_fact_kind(ffd::FactKind::Containment));
  FFD_CHECK(ffd::is_external_fact_kind(ffd::FactKind::Membership));
  FFD_CHECK(ffd::is_external_fact_kind(ffd::FactKind::ExternalAlias));
  FFD_CHECK(!ffd::is_external_fact_kind(ffd::FactKind::Dependency));
  FFD_CHECK(!ffd::is_known_fact_kind(0));
  FFD_CHECK(!ffd::is_known_fact_kind(10));
  FFD_CHECK(ffd::is_known_fact_kind(9));
  FFD_CHECK_EQ(std::string(ffd::error_slug(ffd::ErrorCode::StaleGeneration)),
               std::string("stale_generation"));
  FFD_CHECK_EQ(std::string(ffd::to_string(ffd::PairVerdict::ProvenSharedFate)),
               std::string("proven_shared_fate"));
  FFD_CHECK_EQ(std::string(ffd::to_string(ffd::ConflictKind::AmbiguousAlias)),
               std::string("ambiguous_alias"));
}

FFD_TEST(utf8_validation_rejects_malformed_sequences) {
  FFD_CHECK(ffd::detail::is_valid_utf8("plain ascii"));
  FFD_CHECK(ffd::detail::is_valid_utf8("caf\xc3\xa9"));
  FFD_CHECK(ffd::detail::is_valid_utf8("\xe2\x82\xac"));
  FFD_CHECK(ffd::detail::is_valid_utf8("\xf0\x9f\x9a\x80"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xc3"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xc3\x28"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xc0\xaf"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xed\xa0\x80"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xf4\x90\x80\x80"));
  FFD_CHECK(!ffd::detail::is_valid_utf8("\xff"));
}

FFD_TEST(validation_rules) {
  const ffd::Limits limits;
  ffd::AuthorityId authority;
  authority.value = "dccp.topology";
  FFD_CHECK(ffd::detail::validate_authority(authority, limits).ok());
  authority.value.clear();
  FFD_CHECK_EQ(ffd::detail::validate_authority(authority, limits).code(),
               ffd::ErrorCode::InvalidArgument);
  authority.value = "has space";
  FFD_CHECK_EQ(ffd::detail::validate_authority(authority, limits).code(),
               ffd::ErrorCode::InvalidArgument);
  authority.value = std::string(300, 'a');
  FFD_CHECK_EQ(ffd::detail::validate_authority(authority, limits).code(),
               ffd::ErrorCode::LimitExceeded);

  ffd::ResourceId resource;
  resource.value = "rack-01";
  FFD_CHECK(ffd::detail::validate_resource_id(resource, limits).ok());
  resource.value = std::string("bad") + '\x01';
  FFD_CHECK_EQ(ffd::detail::validate_resource_id(resource, limits).code(),
               ffd::ErrorCode::InvalidArgument);
  resource.value = "\xff\xfe";
  FFD_CHECK_EQ(ffd::detail::validate_resource_id(resource, limits).code(),
               ffd::ErrorCode::InvalidArgument);

  FFD_CHECK(ffd::detail::validate_natural_key("row-a/rack-3", limits).ok());
  FFD_CHECK_EQ(ffd::detail::validate_natural_key("", limits).code(),
               ffd::ErrorCode::InvalidArgument);
  FFD_CHECK_EQ(ffd::detail::validate_natural_key(" padded ", limits).code(),
               ffd::ErrorCode::InvalidArgument);
  FFD_CHECK_EQ(ffd::detail::validate_natural_key(std::string(200, 'k'), limits).code(),
               ffd::ErrorCode::LimitExceeded);

  FFD_CHECK(ffd::detail::validate_display_name("", limits).ok());
  FFD_CHECK(ffd::detail::validate_evidence("cited from BMS export", limits).ok());
  FFD_CHECK_EQ(ffd::detail::validate_evidence(std::string(400, 'e'), limits).code(),
               ffd::ErrorCode::LimitExceeded);

  FFD_CHECK(ffd::detail::validate_domain_id(ffd::DomainId{7}, "subject").ok());
  FFD_CHECK_EQ(ffd::detail::validate_domain_id(ffd::DomainId{}, "subject").code(),
               ffd::ErrorCode::InvalidArgument);
}

FFD_TEST(checked_arithmetic_refuses_overflow) {
  using ffd::detail::checked_add;
  using ffd::detail::checked_cast;
  using ffd::detail::checked_mul;
  using ffd::detail::checked_sub;
  constexpr std::uint64_t maximum = (std::numeric_limits<std::uint64_t>::max)();
  FFD_CHECK(checked_add<std::uint64_t>(1, 2).value() == 3u);
  FFD_CHECK(!checked_add<std::uint64_t>(maximum, 1).has_value());
  FFD_CHECK(!checked_add<std::uint64_t>(maximum, maximum).has_value());
  FFD_CHECK(checked_sub<std::uint64_t>(5, 3).value() == 2u);
  FFD_CHECK(!checked_sub<std::uint64_t>(3, 5).has_value());
  FFD_CHECK(checked_mul<std::uint64_t>(4, 5).value() == 20u);
  FFD_CHECK(!checked_mul<std::uint64_t>(maximum, 2).has_value());
  FFD_CHECK(checked_mul<std::uint64_t>(0, maximum).value() == 0u);
  constexpr std::uint32_t maximum32 = (std::numeric_limits<std::uint32_t>::max)();
  FFD_CHECK(checked_cast<std::uint32_t>(std::uint64_t{7}).value() == 7u);
  FFD_CHECK(!checked_cast<std::uint32_t>(std::uint64_t{maximum32} + 1u).has_value());
  FFD_CHECK(!checked_cast<std::uint32_t>(-1).has_value());
}

FFD_TEST(limits_validation) {
  ffd::Limits limits;
  FFD_CHECK(ffd::detail::validate_limits(limits).ok());
  limits.max_domains = 0;
  FFD_CHECK_EQ(ffd::detail::validate_limits(limits).code(), ffd::ErrorCode::InvalidArgument);
  limits = ffd::Limits{};
  limits.max_natural_key_bytes = limits.max_string_bytes + 1;
  FFD_CHECK_EQ(ffd::detail::validate_limits(limits).code(), ffd::ErrorCode::InvalidArgument);
  limits = ffd::Limits{};
  limits.max_payload_bytes = 16;
  FFD_CHECK_EQ(ffd::detail::validate_limits(limits).code(), ffd::ErrorCode::InvalidArgument);
}

FFD_TEST(result_and_status_behaviour) {
  const ffd::Result<int> good{5};
  FFD_CHECK(good.ok());
  FFD_CHECK_EQ(good.value(), 5);
  const ffd::Result<int> bad{ffd::Error{ffd::ErrorCode::NotFound, "missing"}};
  FFD_CHECK(!bad.ok());
  FFD_CHECK_EQ(bad.code(), ffd::ErrorCode::NotFound);
  FFD_CHECK_EQ(bad.error().detail, std::string("missing"));
  const ffd::Status ok_status;
  FFD_CHECK(ok_status.ok());
  const ffd::Status failure{ffd::Error{ffd::ErrorCode::ReadOnly, "read only"}};
  FFD_CHECK(!failure.ok());
  FFD_CHECK_EQ(std::string(ffd::to_string(failure.code())), std::string("read_only"));
}
