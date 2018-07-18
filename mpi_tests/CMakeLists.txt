cmake_minimum_required(VERSION 3.0)

project (mpi_tests)

set(CMAKE_INSTALL_PREFIX ${INSD})

# Ugly hack: turn space separate options into CMake list
string(STRIP ${COPT} COPT)
string(REPLACE " " ";" COPT ${COPT})
add_compile_options(${COPT})

if (CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(-g -Wall -Werror)
endif (CMAKE_COMPILER_IS_GNUCC)

include_directories(../include ../asic/include)

if (MPID)
  set(MPI_C_COMPILER ${MPID}/bin/mpicc)
endif (MPID)

include(FindMPI)
include_directories(${MPI_C_INCLUDE_PATH})
link_directories(${INSD}/lib)
add_executable(mpi_send mpi_send.c)
set_target_properties(mpi_send PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_send PUBLIC zhpeq zhpeq_util ${MPI_C_LIBRARIES})

install(TARGETS mpi_send DESTINATION libexec)
