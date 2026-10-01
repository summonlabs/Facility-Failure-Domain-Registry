cmake_minimum_required(VERSION 3.21)

project(FacilityFailureDomainRegistry
        VERSION 1.0.0
        DESCRIPTION "Canonical physical failure-domain authority (DCCP boundary 49)"
        HOMEPAGE_URL "https://github.com/summonlabs/Facility-Failure-Domain-Registry"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(FFD_BUILD_TESTS "Build the Facility Failure Domain Registry test suite" OFF)
option(FFD_BUILD_BENCHMARKS "Build the Facility Failure Domain Registry benchmarks" OFF)
option(FFD_ENABLE_ASAN "Instrument code with AddressSanitizer" OFF)
option(FFD_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(FFD_ENABLE_CRASH_INJECTION
       "Compile deterministic durable-publication crash injection points (test support)" OFF)

if(FFD_BUILD_TESTS)
  enable_testing()
endif()

# ---------------------------------------------------------------------------
# Primary library target
# ---------------------------------------------------------------------------
add_library(ffd
  src/canonical.cpp
  src/model.cpp
  src/query.cpp
  src/registry.cpp
  src/sha256.cpp
  src/storage.cpp
  src/types.cpp
  src/validate.cpp)

add_library(FFD::ffd ALIAS ffd)

target_compile_features(ffd PUBLIC cxx_std_20)
target_include_directories(ffd
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

set_target_properties(ffd PROPERTIES
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_definitions(ffd PUBLIC
  FFD_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  FFD_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  FFD_VERSION_PATCH=${PROJECT_VERSION_PATCH})

if(FFD_ENABLE_CRASH_INJECTION)
  target_compile_definitions(ffd PRIVATE FFD_ENABLE_CRASH_INJECTION=1)
endif()

# ---------------------------------------------------------------------------
# Compiler configuration: strict warnings, sanitizers, CRT hardening
# ---------------------------------------------------------------------------
if(MSVC)
  target_compile_options(ffd PRIVATE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /EHsc /GR- /guard:cf)
  target_compile_definitions(ffd PRIVATE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN)
  target_link_options(ffd PRIVATE /guard:cf)
  if(FFD_WARNINGS_AS_ERRORS)
    target_compile_options(ffd PRIVATE /WX)
  endif()
  if(FFD_ENABLE_ASAN)
    # The compiler driver links the ASan runtime itself; the flag is not a
    # linker option and incremental linking cannot consume ASan metadata.
    target_compile_options(ffd PUBLIC /fsanitize=address)
    target_link_options(ffd PUBLIC /INCREMENTAL:NO)
  endif()
else()
  target_compile_options(ffd PRIVATE -Wall -Wextra -Wpedantic)
  if(FFD_WARNINGS_AS_ERRORS)
    target_compile_options(ffd PRIVATE -Werror)
  endif()
  if(FFD_ENABLE_ASAN)
    target_compile_options(ffd PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(ffd PUBLIC -fsanitize=address)
  endif()
endif()

# ---------------------------------------------------------------------------
# Installation and package export
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS ffd
  EXPORT FacilityFailureDomainRegistryTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ffd
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp"
  PATTERN "testing" EXCLUDE)

install(EXPORT FacilityFailureDomainRegistryTargets
  FILE FacilityFailureDomainRegistryTargets.cmake
  NAMESPACE FFD::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FacilityFailureDomainRegistry)

configure_package_config_file(
  cmake/FacilityFailureDomainRegistryConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/FacilityFailureDomainRegistryConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FacilityFailureDomainRegistry)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/FacilityFailureDomainRegistryConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/FacilityFailureDomainRegistryConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/FacilityFailureDomainRegistryConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FacilityFailureDomainRegistry)

# ---------------------------------------------------------------------------
# Tests and benchmarks (never installed)
# ---------------------------------------------------------------------------
if(FFD_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(FFD_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()
