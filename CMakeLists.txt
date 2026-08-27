cmake_minimum_required(VERSION 3.16)

project(KernelShield C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------
# Locate helper modules from libbpf-bootstrap
# --------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf-bootstrap/tools/cmake
)

include(ExternalProject)

# --------------------------------------------------------------------
# Build vendored libbpf
# --------------------------------------------------------------------
ExternalProject_Add(libbpf
    PREFIX libbpf
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf-bootstrap/libbpf/src
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
        CC=${CMAKE_C_COMPILER}
        BUILD_STATIC_ONLY=1
        OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
        DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
        INCLUDEDIR=
        LIBDIR=
        UAPIDIR=
        install
        install_uapi_headers
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS
        ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a
)


# --------------------------------------------------------------------
# Detect architecture
# --------------------------------------------------------------------
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set(ARCH x86)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    set(ARCH arm64)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
    set(ARCH arm)
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()

# --------------------------------------------------------------------
# BpfObject configuration
# --------------------------------------------------------------------
set(BPFOBJECT_BPFTOOL_EXE
    /usr/sbin/bpftool
)

set(BPFOBJECT_VMLINUX_H
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ebpf/vmlinux.h
)

set(LIBBPF_INCLUDE_DIRS
    ${CMAKE_CURRENT_BINARY_DIR}/libbpf
)

set(LIBBPF_LIBRARIES
    ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a
)

find_package(BpfObject REQUIRED)

# --------------------------------------------------------------------
# Generate skeleton
# --------------------------------------------------------------------
bpf_object(process_exec src/ebpf/process_exec.bpf.c)

add_dependencies(process_exec_skel
    libbpf
)

# --------------------------------------------------------------------
# Userspace executable
# --------------------------------------------------------------------
add_executable(kernelshield
    src/main.c
    src/logger.c
    src/detector/process_table.c
    src/detector/correlator.c
    src/detector/evidence_graph.c
    src/detector/attack_episode.c
    src/detector/rules.c
    src/detector/state.c
    src/detector/alert.c
    src/response/response.c
)

target_include_directories(kernelshield PRIVATE
    include
    src/ebpf
)

target_link_libraries(kernelshield
    process_exec_skel
)

install(TARGETS kernelshield DESTINATION bin)
