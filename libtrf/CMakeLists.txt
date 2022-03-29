cmake_minimum_required(VERSION 3.0.0)
project(libtrf LANGUAGES C)

add_definitions(-DTRF_LOG_USE_COLOR)

set(SOURCES
  src/internal/trfi.c
  src/internal/trfi_ncp.c
  src/internal/trfi_ncp_client.c
  src/internal/trfi_ncp_server.c
  src/trf_fabric.c
  src/trf_platform.c
  src/trf_interface.c
  src/trf_msg.c
  src/trf_msg.pb-c.c
  src/trf_ncp.c
  src/trf_ncp_server.c
  src/trf_ncp_client.c
  src/trf_log.c
  src/trf_inet.c
  src/trf.c
)

find_library(Libfabric NAMES fabric)
find_library(Libprotobuf-c NAMES protobuf-c)

add_compile_options(
  "-Wall"
  "-Werror"
  "-Wfatal-errors"
  "-ffast-math"
  "-fdata-sections"
  "-ffunction-sections"
  #"$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
  "-O0;-g3;-ggdb"
)

add_library(trf STATIC ${SOURCES})
set_property(TARGET trf PROPERTY C_STANDARD 99)

include_directories(
  PUBLIC
    ./libs/libfabric/include
    ./libs/protobuf-c
)

target_link_libraries(trf fabric protobuf-c)
target_include_directories(trf
	PUBLIC
		include
	PRIVATE
		src
)

