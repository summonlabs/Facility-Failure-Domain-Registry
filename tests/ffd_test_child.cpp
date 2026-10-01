// Facility Failure Domain Registry - helper process for multiprocess proofs.
//
// Every mode writes its result to the file named by the last positional
// argument (never to a pipe) and returns a process exit code:
//   0 = the requested work completed
//   1 = usage error
//   2 = unexpected failure
//   4 = the store refused to load
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "ffd/registry.hpp"
#include "ffd/testing/crash_injection.hpp"
#include "support.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

using ffdtest::CommitObserver;

std::ofstream g_out;

void write_line(const std::string& line) {
  g_out << line << "\n";
  g_out.flush();
  std::cout << line << "\n";
  std::cout.flush();
}

[[nodiscard]] std::string digest_hex(const ffd::Digest& digest) { return digest.hex(); }

[[nodiscard]] ffd::StoreConfig make_config(const std::string& path) {
  ffd::StoreConfig config;
  config.path = path;
  config.durability = ffd::Durability::DurablePerMutation;
  return config;
}

[[nodiscard]] int report_open_failure(const ffd::Error& error) {
  write_line("ERROR " + std::string(ffd::error_slug(error.code)) + " " + error.detail);
  return 2;
}

void sleep_forever() {
#ifdef _WIN32
  Sleep(INFINITE);
#else
  while (true) {
  }
#endif
}

int mode_hold(const std::vector<std::string>& args) {
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(make_config(args[1]));
  if (!registry.ok()) {
    return report_open_failure(registry.error());
  }
  write_line("READY " + std::to_string(registry.value()->writer_epoch()));
  sleep_forever();
  return 0;
}

int mode_try_writer(const std::vector<std::string>& args) {
  ffd::Result<std::unique_ptr<ffd::Registry>> registry = ffd::Registry::open(make_config(args[1]));
  if (!registry.ok()) {
    write_line("ERROR " + std::string(ffd::error_slug(registry.error().code)));
    return 0;
  }
  write_line("ACQUIRED " + std::to_string(registry.value()->writer_epoch()));
  return 0;
}

int mode_inspect(const std::vector<std::string>& args) {
  ffd::Result<ffd::Snapshot> snapshot = ffd::load_snapshot(make_config(args[1]));
  if (!snapshot.ok()) {
    write_line("ERROR " + std::string(ffd::error_slug(snapshot.error().code)) + " " +
               snapshot.error().detail);
    return 4;
  }
  write_line("GEN " + std::to_string(snapshot.value().generation()) + " DIGEST " +
             digest_hex(snapshot.value().digest()) + " DOMAINS " +
             std::to_string(snapshot.value().domain_count()) + " FACTS " +
             std::to_string(snapshot.value().fact_count()));
  return 0;
}

struct ScriptArguments {
  std::string store;
  std::uint64_t seed{0};
  std::uint64_t rounds{0};
  std::string journal;
  std::uint64_t signal_after{0};
  std::string signal_file;
  std::uint32_t crash_point{0};
  // Number of successful commits after which the injection point is armed, so
  // the process can be terminated at a chosen durable-publication boundary.
  std::uint64_t crash_after{0};
};

int run_script(const ScriptArguments& script, bool print_progress) {
  ffd::Result<std::unique_ptr<ffd::Registry>> registry =
      ffd::Registry::open(make_config(script.store));
  if (!registry.ok()) {
    return report_open_failure(registry.error());
  }
  if (script.crash_point != 0 && script.crash_after == 0) {
    ffd::testing::set_crash_point(static_cast<ffd::testing::CrashPoint>(script.crash_point));
  }
  std::ofstream journal;
  if (!script.journal.empty()) {
    journal.open(script.journal, std::ios::binary | std::ios::app);
    if (!journal) {
      write_line("ERROR journal_open");
      return 2;
    }
  }
  std::uint64_t commits = 0;
  const CommitObserver observer = [&](std::uint64_t generation, const ffd::Digest& digest) {
    ++commits;
    if (journal.is_open()) {
      journal << "GEN " << generation << " " << digest_hex(digest) << "\n";
      journal.flush();
    }
    if (print_progress) {
      write_line("GEN " + std::to_string(generation) + " " + digest_hex(digest));
    }
    if (script.signal_after != 0 && commits == script.signal_after &&
        !script.signal_file.empty()) {
      std::ofstream signal(script.signal_file, std::ios::binary | std::ios::trunc);
      signal << "SIGNAL\n";
      signal.flush();
    }
    if (script.crash_point != 0 && script.crash_after != 0 && commits == script.crash_after) {
      ffd::testing::set_crash_point(static_cast<ffd::testing::CrashPoint>(script.crash_point));
    }
  };
  ffdtest::apply_script(*registry.value(), script.seed, script.rounds, observer);
  const ffd::Status published = registry.value()->publish();
  if (!published.ok()) {
    write_line("ERROR " + std::string(ffd::error_slug(published.code())));
    return 2;
  }
  write_line("DONE " + std::to_string(registry.value()->generation()) + " " +
             digest_hex(registry.value()->digest()) + " COMMITS " + std::to_string(commits));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#endif
  if (argc < 3) {
    std::cout << "usage: ffd_test_child <mode> <store> <out> [extra]\n";
    return 1;
  }
  const std::string mode = argv[1];
  const std::string store = argv[2];
  const std::string out_path = argv[3];
  g_out.open(out_path, std::ios::binary | std::ios::trunc);
  if (!g_out) {
    std::cout << "cannot open output file\n";
    return 1;
  }
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  try {
    if (mode == "hold") {
      return mode_hold(args);
    }
    if (mode == "try-writer") {
      return mode_try_writer(args);
    }
    if (mode == "inspect") {
      return mode_inspect(args);
    }
    if (mode == "append" || mode == "replay" || mode == "write") {
      ScriptArguments script;
      script.store = store;
      // args[0] is the mode, so the script operands start at args[3].
      script.seed = std::stoull(args[3]);
      script.rounds = std::stoull(args[4]);
      if (mode == "write") {
        script.journal = args[5];
        script.signal_after = std::stoull(args[6]);
        script.signal_file = args[7];
        script.crash_point = static_cast<std::uint32_t>(std::stoul(args[8]));
        if (args.size() > 9) {
          script.crash_after = std::stoull(args[9]);
        }
      }
      const int result = run_script(script, mode == "replay");
      if (mode == "write" && result == 0) {
        sleep_forever();
      }
      return result;
    }
    std::cout << "unknown mode: " << mode << "\n";
    return 1;
  } catch (const std::exception& error) {
    write_line(std::string("EXCEPTION ") + error.what());
    return 2;
  }
}
