set(CMAKE_INSTALL_PREFIX ${INSD})

message("COPT " ${COPT})
message("INSD " ${INSD})
message("LIKW " ${LIKW})
message("SIMH " ${SIMH})
message("ZSTA " ${ZSTA})

# Ugly hack: turn space separate options into CMake list
string(STRIP "${COPT}" COPT)
string(REPLACE " " ";" COPT ${COPT})
add_compile_options(${COPT})

if (CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(-g -Wall -Werror -Wpointer-arith)
endif (CMAKE_COMPILER_IS_GNUCC)

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

include_directories(include ${INSD}/include)
link_directories(${INSD}/lib)
