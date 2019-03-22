cmake_minimum_required(VERSION 3.0)

project (libzhpeq)

set(CMAKE_INSTALL_PREFIX ${INSD})

# Ugly hack: turn space separate options into CMake list
string(STRIP "${COPT}" COPT)
string(REPLACE " " ";" COPT ${COPT})
add_compile_options(${COPT})

if (CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(-g -Wall -Werror)
endif (CMAKE_COMPILER_IS_GNUCC)

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

include_directories(include asic/include)

# Interface libraries
add_library(likwid INTERFACE)
if (LIKWID)
  find_library(LIKWID_LIB likwid HINTS ${LIKWID}/lib)
  message("LIKWID_LIB " ${LIKWID_LIB})
  target_link_libraries(likwid INTERFACE ${LIKWID_LIB})
  find_path(LIKWID_INC likwid.h HINTS ${LIKWID}/include)
  message("LIKWID_INC " ${LIKWID_INC})
  target_include_directories(likwid INTERFACE ${LIKWID_INC})
  target_compile_definitions(likwid INTERFACE -DLIKWID_PERFMON)
endif (LIKWID)
add_library(fabric INTERFACE)
if (LIBF)
  target_link_libraries(fabric INTERFACE ${LIBF}/lib/libfabric.so likwid)
  target_include_directories(fabric INTERFACE ${LIBF}/include)
  find_path(SIM_INC hpe_sim_api_linux64.h HINTS ${LIBF}/include)
  message("SIM_INC " ${SIM_INC})
endif (LIBF)

# Build libraries/tests
add_subdirectory(libzhpe_stats)
add_subdirectory(libzhpeq)
add_subdirectory(libzhpeq_backend)
add_subdirectory(libzhpeq_util)
add_subdirectory(libzhpeq_util_fab)
add_subdirectory(lf_tests)
add_subdirectory(tests)
