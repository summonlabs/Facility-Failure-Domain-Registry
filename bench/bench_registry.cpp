// Facility Failure Domain Registry - benchmarks.
//
// Every number below measures completed useful operations, never submission
// latency. Provenance and workload scale are printed with each result:
//   REAL      - the operation really ran against this machine's filesystem,
//               including the durability cost that is claimed for it.
//   SYNTHETIC - the facility graph is generated in memory; no facility hardware,
//               BMS, DCIM, PDU, UPS or cooling device is involved anywhere.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "storage.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using ffd::DomainId;

struct Measurement {
  std::string name;
  std::string provenance;
  std::string scale;
  double operations{0};
  double nanoseconds{0};
  std::string units;
  std::string detail;
};

std::vector<Measurement>& measurements() {
  static std::vector<Measurement> values;
  return values;
}

class Timer {
 public:
  Timer() : start_(Clock::now()) {}
  [[nodiscard]] double nanoseconds() const {
    return static_cast<double>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start_).count());
  }

 private:
  Clock::time_point start_;
};

[[nodiscard]] std::filesystem::path scratch_directory() {
  std::error_code ec;
  std::filesystem::path base = std::filesystem::temp_directory_path(ec);
  if (ec) {
    base = std::filesystem::path(".");
  }
  const std::filesystem::path path = base / "ffd-bench";
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

[[nodiscard]] ffd::MutationContext context(std::uint64_t counter) {
  ffd::MutationContext value;
  value.provenance.authority.value = "bench.authority";
  value.provenance.authority_revision = 1;
  ffd::IdempotencyKey key;
  key.authority = value.provenance.authority;
  key.value = "bench-" + std::to_string(counter);
  value.key = key;
  return value;
}

[[nodiscard]] std::uint64_t store_bytes(const std::filesystem::path& path) {
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  return ec ? 0u : static_cast<std::uint64_t>(size);
}

// ---------------------------------------------------------------------------
// Mutation throughput
// ---------------------------------------------------------------------------
void measure_mutations(const std::filesystem::path& directory, ffd::Durability durability,
                       std::uint64_t count, const char* label) {
  ffd::StoreConfig config;
  config.path = directory / (std::string(label) + ".ffdr");
  config.durability = durability;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
  if (!registry.ok()) {
    std::printf("cannot open store for %s: %s\n", label, registry.error().detail.c_str());
    return;
  }
  std::uint64_t counter = 0;
  const Timer timer;
  for (std::uint64_t i = 0; i < count; ++i) {
    ffd::CreateDomainRequest request;
    request.context = context(++counter);
    request.domain_class = static_cast<ffd::DomainClass>(1 + (i % 10));
    request.natural_key = std::string(label) + "-domain-" + std::to_string(i);
    const ffd::Result<ffd::MutationOutcome> outcome = registry.value()->create_domain(request);
    if (!outcome.ok()) {
      std::printf("mutation %llu failed: %s\n",
                  static_cast<unsigned long long>(i), outcome.error().detail.c_str());
      return;
    }
  }
  const double elapsed = timer.nanoseconds();
  const ffd::Status published = registry.value()->publish();
  if (!published.ok()) {
    std::printf("publish failed: %s\n", published.error().detail.c_str());
    return;
  }
  Measurement measurement;
  measurement.name = std::string("domain creation (") + label + ")";
  measurement.provenance =
      durability == ffd::Durability::DurablePerMutation
          ? "REAL (staged write, flush, read-back verify, atomic replace on this filesystem)"
          : "SYNTHETIC (in-memory generation only; durability cost excluded)";
  measurement.scale = std::to_string(count) + " domains in one store";
  measurement.operations = static_cast<double>(count);
  measurement.nanoseconds = elapsed;
  measurement.units = "domains/s";
  const std::uint64_t bytes = store_bytes(config.path);
  measurement.detail = "store " + std::to_string(bytes) + " bytes (" +
                       std::to_string(count == 0 ? 0 : bytes / count) + " bytes/domain)";
  measurements().push_back(std::move(measurement));
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------
void measure_loads(const std::filesystem::path& store, std::uint64_t loads) {
  ffd::StoreConfig config;
  config.path = store;
  const Timer timer;
  std::size_t domains = 0;
  for (std::uint64_t i = 0; i < loads; ++i) {
    ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(config);
    if (!snapshot.ok()) {
      std::printf("load failed: %s\n", snapshot.error().detail.c_str());
      return;
    }
    domains = snapshot.value().domain_count();
  }
  Measurement measurement;
  measurement.name = "store open + strict decode";
  measurement.provenance = "REAL (reads and verifies the durable file on this filesystem)";
  measurement.scale = std::to_string(loads) + " loads of a " + std::to_string(domains) +
                      "-domain generation";
  measurement.operations = static_cast<double>(loads);
  measurement.nanoseconds = timer.nanoseconds();
  measurement.units = "loads/s";
  measurement.detail = std::to_string(store_bytes(store)) + " bytes per load";
  measurements().push_back(std::move(measurement));
}

void measure_queries(std::uint64_t domain_count, std::uint64_t queries) {
  std::error_code ec;
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path(ec) / "ffd-bench-queries";
  std::filesystem::remove_all(directory, ec);
  std::filesystem::create_directories(directory, ec);
  ffd::StoreConfig config;
  config.path = directory / "graph.ffdr";
  config.durability = ffd::Durability::ExplicitPublish;
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(config);
  if (!registry.ok()) {
    return;
  }
  std::vector<DomainId> domains;
  domains.reserve(static_cast<std::size_t>(domain_count));
  std::uint64_t counter = 0;
  for (std::uint64_t i = 0; i < domain_count; ++i) {
    ffd::CreateDomainRequest request;
    request.context = context(++counter);
    request.domain_class = ffd::DomainClass::Rack;
    request.natural_key = "graph-" + std::to_string(i);
    const ffd::Result<ffd::MutationOutcome> outcome = registry.value()->create_domain(request);
    if (!outcome.ok()) {
      return;
    }
    domains.push_back(outcome.value().domain);
  }
  // A layered synthetic graph: each domain depends on one in the previous layer.
  std::mt19937_64 generator(20260101);
  std::uint64_t edges = 0;
  for (std::size_t index = 8; index < domains.size(); ++index) {
    const std::size_t target = index - 1 - (generator() % 8);
    ffd::DeclareDependencyRequest request;
    request.context = context(++counter);
    request.dependent = domains[index];
    request.target = domains[target];
    if (registry.value()->declare_dependency(request).ok()) {
      ++edges;
    }
  }
  const ffd::Snapshot snapshot = registry.value()->snapshot();

  {
    const Timer timer;
    std::size_t total = 0;
    for (std::uint64_t i = 0; i < queries; ++i) {
      const DomainId target = domains[generator() % domains.size()];
      const ffd::Result<std::vector<DomainId>> upstream = snapshot.upstream_exposure(target);
      if (!upstream.ok()) {
        return;
      }
      total += upstream.value().size();
    }
    Measurement measurement;
    measurement.name = "upstream exposure query";
    measurement.provenance = "SYNTHETIC (generated dependency graph; queries are real)";
    measurement.scale = std::to_string(domain_count) + " domains, " + std::to_string(edges) +
                        " dependency edges, " + std::to_string(queries) + " queries";
    measurement.operations = static_cast<double>(queries);
    measurement.nanoseconds = timer.nanoseconds();
    measurement.units = "queries/s";
    measurement.detail = std::to_string(total) + " exposed domains returned in total";
    measurements().push_back(std::move(measurement));
  }
  {
    const Timer timer;
    std::size_t conflicts = 0;
    for (std::uint64_t i = 0; i < queries; ++i) {
      const DomainId first = domains[generator() % domains.size()];
      const DomainId second = domains[generator() % domains.size()];
      if (first == second) {
        continue;
      }
      const ffd::Result<ffd::PairVerdictResult> verdict = snapshot.pair_verdict(first, second);
      if (!verdict.ok()) {
        return;
      }
      if (verdict.value().verdict == ffd::PairVerdict::Unknown) {
        ++conflicts;
      }
    }
    Measurement measurement;
    measurement.name = "pair failure-fate verdict";
    measurement.provenance = "SYNTHETIC (generated dependency graph; queries are real)";
    measurement.scale = std::to_string(domain_count) + " domains, " + std::to_string(queries) +
                        " pair queries";
    measurement.operations = static_cast<double>(queries);
    measurement.nanoseconds = timer.nanoseconds();
    measurement.units = "queries/s";
    measurement.detail = std::to_string(conflicts) + " unknown verdicts";
    measurements().push_back(std::move(measurement));
  }
  // The registry must be closed before the scratch directory is removed: on
  // Windows an open lock file cannot be deleted, which would leave residue
  // behind in the operator's temporary directory.
  registry.value().reset();
  std::filesystem::remove_all(directory, ec);
}

void report() {
  std::printf("\n%-46s %14s %10s  %s\n", "operation", "per second", "ns/op", "provenance");
  std::printf("%s\n", std::string(120, '-').c_str());
  for (const Measurement& measurement : measurements()) {
    const double seconds = measurement.nanoseconds / 1e9;
    const double per_second = seconds > 0 ? measurement.operations / seconds : 0.0;
    const double per_operation =
        measurement.operations > 0 ? measurement.nanoseconds / measurement.operations : 0.0;
    std::printf("%-46s %14.1f %10.0f  %s\n", measurement.name.c_str(), per_second, per_operation,
                measurement.provenance.c_str());
    std::printf("    scale: %s\n", measurement.scale.c_str());
    if (!measurement.detail.empty()) {
      std::printf("    detail: %s\n", measurement.detail.c_str());
    }
  }
}

}  // namespace

int main() {
  const std::filesystem::path directory = scratch_directory();
  measure_mutations(directory, ffd::Durability::ExplicitPublish, 5000, "in-memory");
  measure_mutations(directory, ffd::Durability::DurablePerMutation, 500, "durable");
  measure_loads(directory / "durable.ffdr", 200);
  measure_queries(2000, 5000);
  report();
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);
  return 0;
}
