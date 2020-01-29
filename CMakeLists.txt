cmake_minimum_required(VERSION 3.2)

set(PROJECT_NAME consensus)
project(${PROJECT_NAME} VERSION 0.5 LANGUAGES CXX ASM C)

if (APPLE)
    set(CMAKE_CXX_STANDARD 17)
else ()
    set(CMAKE_CXX_STANDARD 14)
endif ()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
#set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE "/usr/bin/iwyu")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -DASIO_STANDALONE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wpointer-arith")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -DASIO_STANDALONE -fsanitize=address")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -DASIO_STANDALONE -fsanitize=leak")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -DASIO_STANDALONE -fsanitize=thread")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -DASIO_STANDALONE -fsanitize=undefined")

# Default to a release build
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "Defaulting to Release build")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "The build configuration" FORCE)
endif (NOT CMAKE_BUILD_TYPE)

# If in release build then disable unused variable warnings
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Release build: turn off warnings")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable")
endif ()

#find gmp
find_path(GMP_INCLUDES NAMES gmp.h PATHS $ENV{GMPDIR} ${INCLUDE_INSTALL_DIR})
find_library(GMP_LIBRARIES gmp PATHS $ENV{GMPDIR} ${LIB_INSTALL_DIR})
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG GMP_INCLUDES GMP_LIBRARIES)

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
include(GNUInstallDirs)

# find openssl 
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif ()

# find sodium
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake_dep)
find_package(sodium REQUIRED)
if (sodium_FOUND)
    message(STATUS "Using libsodium ${sodium_VERSION_STRING}")
endif ()

#code coverage
if (ENABLE_COVERAGE)
    message("-- Code coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif ()

if (ENABLE_COVERAGE_LLVM)
    message("-- Code coverage enabled for LLVM")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-instr-generate")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoverage-mapping")
endif ()

#configure vendor directories
set(THIRD_PARTY_MODULE_PATH "${PROJECT_SOURCE_DIR}/3rd")

# -------------------------------------------------------------------------
# catch

#configure directories
set(CATCH_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/Catch")
set(CATCH_INCLUDE_PATH "${CATCH_MODULE_PATH}/include")

#include custom cmake function
include("${CATCH_MODULE_PATH}/contrib/ParseAndAddCatchTests.cmake")

# -------------------------------------------------------------------------
# asio

#configure directories
set(ASIO_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/asio")
set(ASIO_INCLUDE_PATH "${THIRD_PARTY_MODULE_PATH}/asio")

# -------------------------------------------------------------------------
# mapbox variant

#configure directories
set(VARIANT_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/mapbox")
set(VARIANT_INCLUDE_PATH "${THIRD_PARTY_MODULE_PATH}/")

# -------------------------------------------------------------------------
# spdlog

#configure directories
set(SPDLOG_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/spdlog")
set(SPDLOG_INCLUDE_PATH "${SPDLOG_MODULE_PATH}/")

# -------------------------------------------------------------------------
# clara

#configure directories
set(CLARA_MODULE_PATH "${THIRD_PARTY_MODULE_PATH}/Clara")
set(CLARA_INCLUDE_PATH "${CLARA_MODULE_PATH}/include")

# -------------------------------------------------------------------------
#  mcl

set(USE_GMP OFF CACHE BOOL "use gmp" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "use openssl" FORCE)
set(ONLY_LIB ON CACHE BOOL "only lib" FORCE)
add_subdirectory(${THIRD_PARTY_MODULE_PATH}/mcl)
target_include_directories(mcl_st INTERFACE ${THIRD_PARTY_MODULE_PATH}/mcl/include)
target_compile_definitions(mcl_st
        INTERFACE
        -DMCL_USE_VINT
        -DMCL_VINT_FIXED_BUFFER)

add_library(libmcl INTERFACE)
target_link_libraries(libmcl INTERFACE mcl_st)

# -------------------------------------------------------------------------
# noisec

set(USE_SODIUM OFF CACHE BOOL "Use Libsodium for crypto" FORCE)
add_subdirectory(${THIRD_PARTY_MODULE_PATH}/noisec)

# -------------------------------------------------------------------------
#relic
add_subdirectory(${THIRD_PARTY_MODULE_PATH}/relic)
target_include_directories(relic INTERFACE ${THIRD_PARTY_MODULE_PATH}/relic/include)
target_include_directories(relic INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/3rd/relic/include/)
add_library(librelic INTERFACE)
target_link_libraries(librelic INTERFACE relic)

#set variables
set(THIRD_PARTY_INCLUDE_PATH ${VARIANT_INCLUDE_PATH} ${ASIO_INCLUDE_PATH} ${CLARA_INCLUDE_PATH} ${SPDLOG_INCLUDE_PATH})
#set variables for tests
set(TEST_THIRD_PARTY_INCLUDE_PATH ${CATCH_INCLUDE_PATH})


add_subdirectory(lib)
add_subdirectory(apps)

enable_testing()
