cmake_minimum_required(VERSION 3.0)

project (libzhpeq)

set(CMAKE_INSTALL_PREFIX ${INSD})

# Ugly hack: turn space separate options into CMake list
string(STRIP ${COPT} COPT)
string(REPLACE " " ";" COPT ${COPT})
add_compile_options(${COPT})

if (CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(-g -Wall -Werror)
endif (CMAKE_COMPILER_IS_GNUCC)

include_directories(include)

# Driver/helper
add_subdirectory(helper)
add_subdirectory(libzhpeq_util)

# Libraries/tests
if (LIBF)
  include_directories(BEFORE ${LIBF}/include)
  link_directories(${LIBF}/lib)
endif (LIBF)
add_subdirectory(libzhpeq)
add_subdirectory(libzhpeq_backend)
add_subdirectory(libzhpeq_util_fab)
add_subdirectory(ringpong)
add_subdirectory(tests)
