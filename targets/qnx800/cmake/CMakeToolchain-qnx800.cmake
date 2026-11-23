# QNX SDP 8.0 Official Cross-Compilation CMake Toolchain (aarch64le / x86_64)
cmake_minimum_required(VERSION 3.22)
set(CMAKE_SYSTEM_NAME QNX)
set(CMAKE_SYSTEM_VERSION 8.0.0)

if(NOT DEFINED QNX_ARCH)
    set(QNX_ARCH "aarch64le")
endif()

set(CMAKE_SYSTEM_PROCESSOR "${QNX_ARCH}")
set(QNX_COMPILER_TARGET "gcc_nto${QNX_ARCH}")

if(NOT DEFINED ENV{QNX_HOST} OR NOT DEFINED ENV{QNX_TARGET})
    message(FATAL_ERROR "QNX_HOST / QNX_TARGET unset. Run `source ~/qnx800/qnxsdp-env.sh` first.")
endif()

set(CMAKE_C_COMPILER "$ENV{QNX_HOST}/usr/bin/qcc")
set(CMAKE_C_COMPILER_TARGET "${QNX_COMPILER_TARGET}")
set(CMAKE_CXX_COMPILER "$ENV{QNX_HOST}/usr/bin/q++")
set(CMAKE_CXX_COMPILER_TARGET "${QNX_COMPILER_TARGET}")

if(QNX_ARCH STREQUAL "aarch64le")
    set(QNX_SEC_FLAGS "-mbranch-protection=standard -fstack-protector-strong")
else()
    set(QNX_SEC_FLAGS "-fcf-protection=full -fstack-protector-strong")
endif()

set(CMAKE_C_FLAGS_INIT "-D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra ${QNX_SEC_FLAGS}")
set(CMAKE_CXX_FLAGS_INIT "-D_QNX_SOURCE -Wall -Wextra ${QNX_SEC_FLAGS}")
set(CMAKE_FIND_ROOT_PATH "$ENV{QNX_TARGET}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
