// Facility Failure Domain Registry - downstream consumer.
//
// This program only uses the installed public headers and the exported CMake
// target. It exercises the whole documented surface a downstream decision would
// use: write a generation, bind to it, read it back from disk, and detect that
// the binding is stale after the facility changes.
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "ffd/registry.hpp"

namespace {

int fail(const std::string& message) {
  std::printf("CONSUMER FAILED: %s\n", message.c_str());
  return 1;
}

ffd::MutationContext context(const char* authority, const std::string& key) {
  ffd::MutationContext value;
  value.provenance.authority.value = authority;
  value.provenance.authority_revision = 1;
  ffd::IdempotencyKey idempotency;
  idempotency.authority = value.provenance.authority;
  idempotency.value = key;
  value.key = idempotency;
  return value;
}

}  // namespace

int main(int argc, char** argv) {
  std::error_code ec;
  const std::filesystem::path base =
      argc > 1 ? std::filesystem::path(argv[1])
               : std::filesystem::temp_directory_path(ec) / "ffd-consumer";
  std::filesystem::create_directories(base, ec);
  const std::filesystem::path store = base / "consumer.ffdr";
  std::filesystem::remove(store, ec);
  {
    std::filesystem::path epoch = store;
    epoch += L".epoch";
    std::filesystem::remove(epoch, ec);
  }

  ffd::StoreConfig config;
  config.path = store;
  config.durability = ffd::Durability::DurablePerMutation;

  ffd::ModelBinding binding;
  {
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
    if (!registry.ok()) {
      return fail("open: " + registry.error().detail);
    }
    ffd::CreateDomainRequest room;
    room.context = context("consumer.authority", "room");
    room.domain_class = ffd::DomainClass::Room;
    room.natural_key = "room-1";
    const ffd::Result<ffd::MutationOutcome> created_room = registry.value()->create_domain(room);
    if (!created_room.ok()) {
      return fail("create room: " + created_room.error().detail);
    }
    ffd::CreateDomainRequest rack;
    rack.context = context("consumer.authority", "rack");
    rack.domain_class = ffd::DomainClass::Rack;
    rack.natural_key = "rack-1";
    const ffd::Result<ffd::MutationOutcome> created_rack = registry.value()->create_domain(rack);
    if (!created_rack.ok()) {
      return fail("create rack: " + created_rack.error().detail);
    }
    ffd::DeclareContainmentRequest containment;
    containment.context = context("consumer.authority", "containment");
    containment.parent = created_room.value().domain;
    containment.child = created_rack.value().domain;
    if (!registry.value()->declare_containment(containment).ok()) {
      return fail("declare containment");
    }
    ffd::AddMembershipRequest membership;
    membership.context = context("consumer.authority", "membership");
    membership.domain = created_rack.value().domain;
    membership.resource.authority.value = "asset.registry";
    membership.resource.resource.value = "asset-1";
    if (!registry.value()->add_membership(membership).ok()) {
      return fail("add membership");
    }
    binding = registry.value()->snapshot().binding();
  }

  // Read-only consumption of the published generation.
  ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(config);
  if (!snapshot.ok()) {
    return fail("load: " + snapshot.error().detail);
  }
  const ffd::Status verified = snapshot.value().verify_binding(binding);
  if (!verified.ok()) {
    return fail(std::string("binding: ") + ffd::to_string(verified.code()));
  }
  const ffd::Result<std::vector<ffd::DomainId>> downstream =
      snapshot.value().downstream_exposure(ffd::DomainId{1});
  if (!downstream.ok() || downstream.value().size() != 1) {
    return fail("exposure query");
  }
  const ffd::Result<std::vector<ffd::DomainId>> containing = snapshot.value().containing_domains(
      [&] {
        ffd::ExternalRef ref;
        ref.authority.value = "asset.registry";
        ref.resource.value = "asset-1";
        return ref;
      }());
  if (!containing.ok() || containing.value().size() != 1U) {
    return fail("containing domains query");
  }

  // A later generation makes the earlier binding explicitly stale.
  {
    ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
    if (!registry.ok()) {
      return fail("reopen: " + registry.error().detail);
    }
    ffd::CreateDomainRequest extra;
    extra.context = context("consumer.authority", "extra");
    extra.domain_class = ffd::DomainClass::Rack;
    extra.natural_key = "rack-2";
    if (!registry.value()->create_domain(extra).ok()) {
      return fail("create extra");
    }
  }
  ffd::Result<ffd::Snapshot> later = ffd::load_snapshot(config);
  if (!later.ok()) {
    return fail("reload");
  }
  const ffd::Status stale = later.value().verify_binding(binding);
  if (stale.ok() || stale.code() != ffd::ErrorCode::StaleGeneration) {
    return fail("stale binding was not detected");
  }

  std::printf("CONSUMER OK generation=%llu digest=%s version=%s boundary=%u\n",
              static_cast<unsigned long long>(binding.generation), binding.digest.hex().c_str(),
              ffd::version_string(), ffd::kDccpBoundary);
  std::filesystem::remove_all(base, ec);
  return 0;
}
