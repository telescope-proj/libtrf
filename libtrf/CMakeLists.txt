cmake_minimum_required(VERSION 3.0.0)
project(libtrf LANGUAGES C)

include_directories(include)

set(SOURCES
    src/trf.c
)

find_library(Libfabric NAMES fabric)

add_compile_options(
  "-Wall"
  "-Werror"
  "-Wfatal-errors"
  "-ffast-math"
  "-fdata-sections"
  "-ffunction-sections"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

add_library(trf STATIC ${SOURCES})

target_include_directories(trf
	INTERFACE
		include
	PRIVATE
		src
)