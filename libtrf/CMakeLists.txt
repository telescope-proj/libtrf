cmake_minimum_required(VERSION 3.0.0)
project(libtrf LANGUAGES C)

include_directories(include)
add_definitions(-DTRF_LOG_USE_COLOR)

set(SOURCES
  src/trf_interface.c
  src/trf.c
  src/trf_msg.c
  src/trf_msg.pb-c.c
  src/trf_ncp.c
  src/trf_log.c
  #src/trf_preflight.c
  src/trf_inet.c
  src/trf_internal.c
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

target_include_directories(trf
	INTERFACE
		include
	PRIVATE
		src
)