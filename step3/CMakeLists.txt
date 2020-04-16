# zhpe-support core; libfabric; and MPI built

cmake_minimum_required(VERSION 3.5)

project (libzhpeq3)

include("../common.cmake")
include("../libzhpe_stats.cmake")

add_subdirectory(mpi_tests)
