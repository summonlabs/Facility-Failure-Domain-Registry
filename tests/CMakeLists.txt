# Test suite. Tests are plain executables registered with CTest; no test
# carries a timeout property and no command wrapper imposes one.

add_library(ffd_test_support STATIC test_main.cpp support.cpp)
target_link_libraries(ffd_test_support PUBLIC FFD::ffd)
target_compile_features(ffd_test_support PUBLIC cxx_std_20)
target_include_directories(ffd_test_support PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/src)

if(MSVC)
  target_compile_options(ffd_test_support PUBLIC /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  target_compile_definitions(ffd_test_support PUBLIC
    _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  if(FFD_WARNINGS_AS_ERRORS)
    target_compile_options(ffd_test_support PUBLIC /WX)
  endif()
else()
  target_compile_options(ffd_test_support PUBLIC -Wall -Wextra)
  if(FFD_WARNINGS_AS_ERRORS)
    target_compile_options(ffd_test_support PUBLIC -Werror)
  endif()
endif()

# Helper process used by the multiprocess and crash-recovery proofs.
add_executable(ffd_test_child ffd_test_child.cpp)
target_link_libraries(ffd_test_child PRIVATE ffd_test_support)

function(ffd_add_test stem)
  add_executable(ffd_${stem} ${stem}.cpp)
  target_link_libraries(ffd_${stem} PRIVATE ffd_test_support)
  # Tests spawn the helper process, so it must always match the library build.
  add_dependencies(ffd_${stem} ffd_test_child)
  add_test(NAME ffd_${stem} COMMAND ffd_${stem})
  set_tests_properties(ffd_${stem} PROPERTIES
    ENVIRONMENT "FFD_TEST_CHILD_PATH=$<TARGET_FILE:ffd_test_child>")
endfunction()

ffd_add_test(test_types)
ffd_add_test(test_model)
ffd_add_test(test_query)
ffd_add_test(test_storage)
ffd_add_test(test_determinism)
ffd_add_test(test_adversarial)
ffd_add_test(test_property)
ffd_add_test(test_multiprocess)
ffd_add_test(test_lifecycle)
# FFD_TEST_LIST_BELOW
