// Facility Failure Domain Registry - test support.
#include "test_framework.hpp"

#include <cstddef>
#include <iostream>
#include <string>

namespace {

// Test progress must survive abrupt termination of a test body, so every line is
// flushed as it is produced.
struct FlushingReporter {
  FlushingReporter() { std::cout.setf(std::ios::unitbuf); }
};

FlushingReporter g_flushing_reporter;

}  // namespace

namespace ffdtest {
namespace {

bool g_current_failed = false;
std::size_t g_failures = 0;

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(const char* name, Body body) {
  registry().push_back(TestCase{std::string(name), std::move(body)});
}

void report_failure(const char* file, int line, const std::string& message) {
  g_current_failed = true;
  ++g_failures;
  std::cout << "  FAIL " << file << ":" << line << ": " << message << "\n";
}

int run_all(int argc, char** argv) {
  const std::string filter = argc > 1 ? std::string(argv[1]) : std::string();
  std::size_t executed = 0;
  std::size_t failed_tests = 0;
  for (const TestCase& test : registry()) {
    if (!filter.empty() && test.name.rfind(filter, 0) != 0) {
      continue;
    }
    ++executed;
    g_current_failed = false;
    std::cout << "RUN  " << test.name << "\n";
    try {
      test.body();
    } catch (const AssertionFailure& failure) {
      report_failure("<body>", 0, "aborted after requirement: " + failure.message);
    } catch (const std::exception& error) {
      report_failure("<body>", 0, std::string("unexpected exception: ") + error.what());
    } catch (...) {
      report_failure("<body>", 0, "unexpected non-standard exception");
    }
    if (g_current_failed) {
      ++failed_tests;
      std::cout << "FAIL " << test.name << "\n";
    } else {
      std::cout << "PASS " << test.name << "\n";
    }
  }
  std::cout << "tests=" << executed << " failed=" << failed_tests
            << " assertion_failures=" << g_failures << "\n";
  if (executed == 0) {
    std::cout << "no test matched the filter\n";
    return 2;
  }
  return failed_tests == 0 ? 0 : 1;
}

}  // namespace ffdtest

int main(int argc, char** argv) { return ffdtest::run_all(argc, argv); }
