# zhpe-support core; libfabric; and MPI built

cmake_minimum_required(VERSION 3.5)

project (libzhpeq3)

include("../common.cmake")
include("../libfabric.cmake")
include("../libzhpe_stats.cmake")
include("../likwid.cmake")

add_subdirectory(mpi_tests)
