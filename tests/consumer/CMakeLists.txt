# Independent out-of-tree consumer used to prove the installed package.
# This project is deliberately not part of the parent build.
cmake_minimum_required(VERSION 3.21)

project(FacilityFailureDomainConsumer
        VERSION 1.0.0
        DESCRIPTION "Downstream consumer of the installed Facility Failure Domain Registry package"
        LANGUAGES CXX)

find_package(FacilityFailureDomainRegistry 1.0 REQUIRED)

add_executable(ffd_consumer main.cpp)
target_compile_features(ffd_consumer PRIVATE cxx_std_20)
target_link_libraries(ffd_consumer PRIVATE FFD::ffd)

if(MSVC)
  target_compile_options(ffd_consumer PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /WX)
endif()
