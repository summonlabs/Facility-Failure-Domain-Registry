// Facility Failure Domain Registry - test support.
#include "support.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>

#include <process.h>
#else
#include <unistd.h>
#endif

namespace ffdtest {
namespace {

std::uint64_t process_id() noexcept {
#ifdef _WIN32
  return static_cast<std::uint64_t>(_getpid());
#else
  return static_cast<std::uint64_t>(::getpid());
#endif
}

bool env_flag(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && value[0] != '0' && value[0] != '\0';
}

}  // namespace

ScratchDir::ScratchDir(const std::string& label) {
  static std::uint64_t counter = 0;
  ++counter;
  std::error_code ec;
  const std::filesystem::path base = std::filesystem::temp_directory_path(ec);
  const std::filesystem::path root = (ec ? std::filesystem::path(".") : base) / "ffd-tests";
  std::filesystem::create_directories(root, ec);
  path_ = root / (label + "-" + std::to_string(process_id()) + "-" + std::to_string(counter));
  std::filesystem::remove_all(path_, ec);
  std::filesystem::create_directories(path_, ec);
  keep_ = env_flag("FFD_KEEP_SCRATCH");
}

ScratchDir::~ScratchDir() {
  std::error_code ec;
  if (keep_) {
    std::cout << "  scratch kept at " << path_.string() << "\n";
    return;
  }
  std::filesystem::remove_all(path_, ec);
}

Rng::Rng(std::uint64_t seed) noexcept
    : state_(seed == 0 ? 0x9e3779b97f4a7c15ull : seed), seed_(seed == 0 ? 1 : seed) {}

std::uint64_t Rng::next() noexcept {
  std::uint64_t x = state_;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  state_ = x;
  return x * 0x2545f4914f6cdd1dull;
}

std::uint32_t Rng::below(std::uint32_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  return static_cast<std::uint32_t>(next() % bound);
}

bool Rng::chance(std::uint32_t numerator, std::uint32_t denominator) noexcept {
  if (denominator == 0) {
    return false;
  }
  return below(denominator) < numerator;
}

ffd::MutationContext make_context(const char* authority_name, std::uint64_t revision,
                                  const std::string& key_value, std::uint64_t expected_generation) {
  ffd::MutationContext context;
  context.provenance.authority = authority(authority_name);
  context.provenance.authority_revision = revision;
  context.expected_generation = expected_generation;
  ffd::IdempotencyKey key;
  key.authority = authority(authority_name);
  key.value = key_value;
  context.key = key;
  return context;
}

ffd::MutationContext make_context_without_key(const char* authority_name, std::uint64_t revision) {
  ffd::MutationContext context;
  context.provenance.authority = authority(authority_name);
  context.provenance.authority_revision = revision;
  return context;
}

std::string index_key(const char* prefix, std::uint64_t counter) {
  return std::string(prefix) + "-" + std::to_string(counter);
}

ffd::AuthorityId authority(const char* value) {
  ffd::AuthorityId id;
  id.value = value;
  return id;
}

ffd::ExternalRef external(const char* owner, const std::string& resource) {
  ffd::ExternalRef ref;
  ref.authority = authority(owner);
  ref.resource.value = resource;
  return ref;
}

bool read_file_bytes(const std::filesystem::path& path, std::vector<std::uint8_t>& out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
  return true;
}

bool write_file_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  return stream.good();
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------
std::filesystem::path child_executable_path() {
#ifdef _WIN32
  const char* from_environment = std::getenv("FFD_TEST_CHILD_PATH");
  if (from_environment != nullptr && from_environment[0] != '\0') {
    std::error_code ec;
    const std::filesystem::path candidate(from_environment);
    if (std::filesystem::exists(candidate, ec) && !ec) {
      return candidate;
    }
  }
  std::vector<wchar_t> buffer(4096);
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) {
    return {};
  }
  const std::filesystem::path self(std::wstring(buffer.data(), length));
  return self.parent_path() / L"ffd_test_child.exe";
#else
  return {};
#endif
}

#ifdef _WIN32
ChildProcess::~ChildProcess() {
  if (running()) {
    kill();
  }
  release();
}

void ChildProcess::release() {
  if (thread_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(thread_));
    thread_ = nullptr;
  }
  if (process_ != nullptr) {
    CloseHandle(static_cast<HANDLE>(process_));
    process_ = nullptr;
  }
  pid_ = 0;
}

bool ChildProcess::running() const {
  if (process_ == nullptr) {
    return false;
  }
  return WaitForSingleObject(static_cast<HANDLE>(process_), 0) == WAIT_TIMEOUT;
}

int ChildProcess::wait() {
  if (process_ == nullptr) {
    return -1;
  }
  const DWORD waited = WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
  if (waited != WAIT_OBJECT_0) {
    return -1;
  }
  DWORD code = 0;
  if (GetExitCodeProcess(static_cast<HANDLE>(process_), &code) == FALSE) {
    return -1;
  }
  return static_cast<int>(code);
}

void ChildProcess::kill() {
  if (process_ == nullptr) {
    return;
  }
  TerminateProcess(static_cast<HANDLE>(process_), 3);
  WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
}

bool ChildProcess::spawn(const std::vector<std::string>& arguments, ChildProcess& out) {
  const std::filesystem::path executable = child_executable_path();
  if (executable.empty()) {
    return false;
  }
  std::wstring command = L"\"" + executable.wstring() + L"\"";
  for (const std::string& argument : arguments) {
    command += L" \"";
    command += std::filesystem::path(argument).wstring();
    command += L"\"";
  }
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  if (CreateProcessW(executable.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information) == FALSE) {
    return false;
  }
  out.release();
  out.process_ = information.hProcess;
  out.thread_ = information.hThread;
  out.pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  return true;
}

bool wait_for_file(const std::filesystem::path& path, const ChildProcess& child) {
  // Waits for content, not mere existence: a child creates its output file
  // before it has anything to say, so existence alone is not the condition.
  std::error_code ec;
  while (true) {
    if (std::filesystem::exists(path, ec) && !ec) {
      const std::uintmax_t size = std::filesystem::file_size(path, ec);
      if (!ec && size > 0) {
        return true;
      }
    }
    if (!child.running()) {
      return false;
    }
    Sleep(1);
  }
}

#else

ChildProcess::~ChildProcess() = default;
void ChildProcess::release() {}
bool ChildProcess::running() const { return false; }
int ChildProcess::wait() { return -1; }
void ChildProcess::kill() {}
bool ChildProcess::spawn(const std::vector<std::string>&, ChildProcess&) { return false; }
bool wait_for_file(const std::filesystem::path&, const ChildProcess&) { return false; }

#endif

// ---------------------------------------------------------------------------
// Deterministic mutation script
// ---------------------------------------------------------------------------
namespace {

// Returns the outcome for callers that need it; several script steps only
// require the commit to have happened.
ffd::MutationOutcome commit_or_throw(ffd::Result<ffd::MutationOutcome> result,
                                     const CommitObserver& observer) {
  if (!result.ok()) {
    throw std::runtime_error("script mutation failed: " + result.error().detail);
  }
  const ffd::MutationOutcome outcome = result.value();
  observer(outcome.generation, outcome.digest);
  return outcome;
}

[[nodiscard]] bool has_extra_containment(std::uint64_t round) noexcept { return round > 0; }
[[nodiscard]] bool has_shared_fate(std::uint64_t round) noexcept {
  return round >= 3 && round % 3 == 0;
}
[[nodiscard]] bool has_independence(std::uint64_t round) noexcept {
  return round >= 6 && round % 6 == 0;
}

}  // namespace

void apply_script(ffd::Registry& registry, std::uint64_t seed, std::uint64_t rounds,
                  const CommitObserver& on_commit) {
  const CommitObserver observer = on_commit ? on_commit : CommitObserver{};
  std::vector<ffd::DomainId> domains;
  domains.reserve(static_cast<std::size_t>(rounds));
  std::uint64_t counter = 0;
  const auto next_context = [&](const char* who) {
    ++counter;
    return make_context(who, 1, "script-" + std::to_string(seed) + "-" + std::to_string(counter));
  };

  for (std::uint64_t round = 0; round < rounds; ++round) {
    ffd::CreateDomainRequest create;
    create.context = next_context("authority.alpha");
    create.domain_class = ffd::DomainClass::Rack;
    create.natural_key = "d-" + std::to_string(seed) + "-" + std::to_string(round);
    create.display_name = "domain " + std::to_string(round);
    const ffd::DomainId id = commit_or_throw(registry.create_domain(create), observer).domain;
    domains.push_back(id);

    ffd::AddMembershipRequest membership;
    membership.context = next_context("authority.alpha");
    membership.domain = id;
    membership.resource = external("asset.registry",
                                   "asset-" + std::to_string(seed) + "-" + std::to_string(round));
    commit_or_throw(registry.add_membership(membership), observer);

    if (has_extra_containment(round)) {
      ffd::DeclareContainmentRequest containment;
      containment.context = next_context("authority.alpha");
      containment.parent = domains[static_cast<std::size_t>(round - 1)];
      containment.child = id;
      commit_or_throw(registry.declare_containment(containment), observer);
    }
    if (has_shared_fate(round)) {
      ffd::DeclareSharedFateRequest shared;
      shared.context = next_context("authority.alpha");
      shared.a = domains[static_cast<std::size_t>(round - 3)];
      shared.b = id;
      commit_or_throw(registry.declare_shared_fate(shared), observer);
    }
    if (has_independence(round)) {
      ffd::DeclareIndependenceRequest independence;
      independence.context = next_context("authority.beta");
      independence.a = domains[static_cast<std::size_t>(round - 6)];
      independence.b = id;
      commit_or_throw(registry.declare_independence(independence), observer);
    }
  }
}

std::uint64_t script_mutations(std::uint64_t rounds) {
  std::uint64_t total = 0;
  for (std::uint64_t round = 0; round < rounds; ++round) {
    total += 2;
    if (has_extra_containment(round)) {
      ++total;
    }
    if (has_shared_fate(round)) {
      ++total;
    }
    if (has_independence(round)) {
      ++total;
    }
  }
  return total;
}

}  // namespace ffdtest
