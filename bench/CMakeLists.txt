# Benchmarks measure completed useful operations and are never registered as
# tests, so no timing policy can turn a benchmark into a pass/fail gate.
add_executable(ffd_bench_registry bench_registry.cpp)
target_link_libraries(ffd_bench_registry PRIVATE FFD::ffd)
target_compile_features(ffd_bench_registry PRIVATE cxx_std_20)
target_include_directories(ffd_bench_registry PRIVATE ${CMAKE_SOURCE_DIR}/src)

if(MSVC)
  target_compile_options(ffd_bench_registry PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  target_compile_definitions(ffd_bench_registry PRIVATE
    _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  if(FFD_WARNINGS_AS_ERRORS)
    target_compile_options(ffd_bench_registry PRIVATE /WX)
  endif()
endif()
