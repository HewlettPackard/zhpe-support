# Build zhpe-support core; libfabric and MPI asssumed not to exist

cmake_minimum_required(VERSION 3.5)

project (libzhpeq1)

include("../common.cmake")
include("../simh.cmake")

include_directories(BEFORE ../include asic/include)

add_subdirectory(libzhpe_stats)
add_subdirectory(libzhpeq)
add_subdirectory(libzhpeq_util)

install(
  FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_util_fab_atomic.h
  DESTINATION include)
