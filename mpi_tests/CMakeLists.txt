cmake_minimum_required(VERSION 3.0)

project (mpi_tests)

set(CMAKE_INSTALL_PREFIX ${INSD})

# Ugly hack: turn space separate options into CMake list
string(STRIP "${COPT}" COPT)
string(REPLACE " " ";" COPT ${COPT})
add_compile_options(${COPT})

if (CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(-g -Wall -Werror)
endif (CMAKE_COMPILER_IS_GNUCC)

include_directories(../include ../asic/include ${INSD}/include)
link_directories(${INSD}/lib)

if (MPID)
  set(MPI_C_COMPILER ${MPID}/bin/mpicc)
endif (MPID)

include(FindMPI)
include_directories(AFTER ${MPI_C_INCLUDE_PATH})

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_library(zhpeq_lf SHARED zhpeq_lf.c)
target_link_libraries(zhpeq_lf PRIVATE zhpeq_util PUBLIC fabric)

install(TARGETS zhpeq_lf DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/../include/zhpeq_lf.h DESTINATION include)

add_executable(mpi_lf_threads mpi_lf_threads.c)
set_target_properties(mpi_lf_threads PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_lf_threads
  PRIVATE zhpeq_lf PUBLIC fabric Threads::Threads ${MPI_C_LIBRARIES})

add_executable(mpi_send mpi_send.c)
set_target_properties(mpi_send PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_send PRIVATE zhpeq PUBLIC ${MPI_C_LIBRARIES})

install(TARGETS mpi_lf_threads mpi_send DESTINATION libexec)
