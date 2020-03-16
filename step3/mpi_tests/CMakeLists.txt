set(MPI_C_COMPILER ${INSD}/bin/mpicc)
set(MPI_CXX_COMPILER ${INSD}/bin/mpicxx)

include(FindMPI)
include_directories(AFTER ${MPI_C_INCLUDE_PATH})

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_compile_options(-D_ZHPEQ_TEST_COMPAT_)

add_library(zhpeq_lf SHARED zhpeq_lf.c)
target_link_libraries(zhpeq_lf PUBLIC zhpeq_util fabric)

install(TARGETS zhpeq_lf DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_lf.h DESTINATION include)

add_executable(mpi_lf_threads mpi_lf_threads.c)
set_target_properties(mpi_lf_threads PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_lf_threads PUBLIC zhpeq_lf Threads::Threads ${MPI_C_LIBRARIES})

add_executable(mpi_send mpi_send.c)
set_target_properties(mpi_send PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_send PUBLIC fabric zhpe_stats zhpeq_util ${MPI_C_LIBRARIES})

install(TARGETS mpi_lf_threads mpi_send DESTINATION libexec)
