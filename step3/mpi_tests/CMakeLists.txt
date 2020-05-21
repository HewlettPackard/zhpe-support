include(FindMPI)
include_directories(AFTER ${MPI_C_INCLUDE_PATH})

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_compile_options(-D_ZHPEQ_TEST_COMPAT_)

add_library(zhpeq_lf SHARED zhpeq_lf.c)
target_link_libraries(zhpeq_lf PUBLIC zhpeq_util fabric)

install(TARGETS zhpeq_lf DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_lf.h DESTINATION include)

add_executable(mpi_barrier mpi_barrier.c)
set_target_properties(mpi_barrier PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_barrier PUBLIC zhpe_stats zhpeq_util ${MPI_C_LIBRARIES})

add_executable(mpi_exit mpi_exit.c)
set_target_properties(mpi_exit PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_exit PUBLIC zhpeq_util ${MPI_C_LIBRARIES})

add_executable(mpi_inv mpi_inv.c)
set_target_properties(mpi_inv PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_inv PUBLIC zhpeq_util ${MPI_C_LIBRARIES})

add_executable(mpi_lf_threads mpi_lf_threads.c)
set_target_properties(mpi_lf_threads PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_lf_threads PUBLIC zhpeq_lf Threads::Threads ${MPI_C_LIBRARIES})

add_executable(mpi_send mpi_send.c)
set_target_properties(mpi_send PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_send PUBLIC zhpe_stats zhpeq_util ${MPI_C_LIBRARIES})

add_executable(mpi_xingflood mpi_xingflood.c)
set_target_properties(mpi_xingflood PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(
  mpi_xingflood PUBLIC zhpe_stats zhpeq zhpeq_util ${MPI_C_LIBRARIES})

add_executable(mpi_zbw mpi_zbw.c)
set_target_properties(mpi_zbw PROPERTIES LINK_FLAGS ${MPI_C_LINK_FLAGS})
target_link_libraries(mpi_zbw PUBLIC zhpe_stats zhpeq_util ${MPI_C_LIBRARIES})

install(
  TARGETS
  mpi_barrier
  mpi_exit
  mpi_inv
  mpi_lf_threads
  mpi_send
  mpi_xingflood
  mpi_zbw
  DESTINATION libexec)
