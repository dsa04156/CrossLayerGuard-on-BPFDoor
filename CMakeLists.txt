cmake_minimum_required(VERSION 3.15)
project(crosslayer-guard C CXX)
option(CLG_INTERFACE "Network interface to attach probes" "enp0s8")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# 설치 경로
set(BPF_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib/crosslayer-ebpf"
    CACHE PATH "Where to install eBPF object files")

# include / link dirs
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/ebpf
  ${LIBBPF_INCLUDE_DIRS}
)
link_directories(${LIBBPF_LIBRARY_DIRS})

# ── 1) eBPF 오브젝트 빌드 함수 ─────────────────────────────────────────
function(build_bpf obj_name src)
  set(output "${CMAKE_BINARY_DIR}/ebpf/${obj_name}")
  add_custom_command(
    OUTPUT ${output}
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/ebpf"
    COMMAND clang
            -O2 -g -Wall -target bpf
            -I${CMAKE_SOURCE_DIR}/ebpf
            -c ${CMAKE_SOURCE_DIR}/${src}
            -o ${output}
    DEPENDS ${CMAKE_SOURCE_DIR}/${src} ${CMAKE_SOURCE_DIR}/ebpf/common.h
    COMMENT "Building eBPF object ${obj_name}"
    VERBATIM
  )
  add_custom_target(${obj_name}_target DEPENDS ${output})
  list(APPEND BPF_OBJECTS ${output})
  set(BPF_OBJECTS "${BPF_OBJECTS}" PARENT_SCOPE)
endfunction()

build_bpf("xdp_record.o"      "ebpf/xdp_probe.c")
build_bpf("tc_record.o"       "ebpf/tc_ingress_probe.c")
build_bpf("sock_record.o"     "ebpf/socket_filter_probe.c")
build_bpf("ctrl_probe.o"      "ebpf/syscall_probe.c")

add_custom_target(all_bpf DEPENDS ${BPF_OBJECTS})

# ── 2) 유저스페이스 라이브러리 (loader + aggregator + validator) ───────
add_library(clg_user STATIC
    src/loader.cpp
    src/aggregator.cpp
    src/validator.cpp
)
target_include_directories(clg_user
    PUBLIC 
      ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(clg_user
    PRIVATE
      ${LIBBPF_LIBRARIES}
      pthread
      rt
)

# ── 3) CLI 도구 (clgctl) ────────────────────────────────────────────────
add_executable(clgctl
    cli/clgctl.cpp
)
add_dependencies(clgctl all_bpf)
target_include_directories(clgctl
    PRIVATE
      ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(clgctl
    PRIVATE
      clg_user           # clg_start_aggregator 등 심볼 제공
      ${LIBBPF_LIBRARIES}
      pthread
      rt
)

# ── 4) Debug reader 도구 (tools/read_record_debug_test.c) ───────────────
add_executable(debug_reader
    tools/read_record_debug_test.c
)
add_dependencies(debug_reader all_bpf)
target_link_libraries(debug_reader
    PRIVATE
      ${LIBBPF_LIBRARIES}
      pthread
      rt
)

# ── 5) Systemd 서비스 유닛 설치 ───────────────────────────────
configure_file(
    ${CMAKE_SOURCE_DIR}/system/crosslayer.service.in
    ${CMAKE_BINARY_DIR}/crosslayer.service
    @ONLY
)

install(FILES ${CMAKE_BINARY_DIR}/crosslayer.service
        DESTINATION /etc/systemd/system)

# post-install hook: systemd 등록 스크립트
install(CODE "
    execute_process(COMMAND systemctl daemon-reexec)
    execute_process(COMMAND systemctl enable crosslayer.service)
    execute_process(COMMAND systemctl restart crosslayer.service)
    message(STATUS \"Systemd service installed and started.\")
")


# ── 5) 설치 설정 ─────────────────────────────────────────────────────
install(DIRECTORY include/ DESTINATION include)

install(TARGETS clg_user
        ARCHIVE DESTINATION lib)

install(TARGETS clgctl
        RUNTIME DESTINATION bin)

install(FILES
    ${CMAKE_BINARY_DIR}/ebpf/xdp_record.o
    ${CMAKE_BINARY_DIR}/ebpf/tc_record.o
    ${CMAKE_BINARY_DIR}/ebpf/sock_record.o
    ${CMAKE_BINARY_DIR}/ebpf/ctrl_probe.o
  DESTINATION ${BPF_INSTALL_DIR}
)
