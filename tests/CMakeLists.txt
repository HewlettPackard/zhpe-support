add_executable(libzhpeq_ld libzhpeq_ld.c)
target_link_libraries(libzhpeq_ld zhpeq zhpeq_util)
add_executable(libzhpeq_util_log libzhpeq_util_log.c)
target_link_libraries(libzhpeq_util_log zhpeq_util)
add_executable(libzhpeq_qalloc libzhpeq_qalloc.c)
target_link_libraries(libzhpeq_qalloc zhpeq zhpeq_util)
add_executable(libzhpeq_qattr libzhpeq_qattr.c)
target_link_libraries(libzhpeq_qattr zhpeq zhpeq_util)
add_executable(libzhpeq_regtime libzhpeq_regtime.c)
target_link_libraries(libzhpeq_regtime zhpeq zhpeq_util)
add_executable(xingpong xingpong.c)
target_link_libraries(xingpong zhpeq zhpeq_util zhpeq_util_fab)
install(
  TARGETS
  libzhpeq_ld
  libzhpeq_qalloc
  libzhpeq_qattr
  libzhpeq_regtime
  libzhpeq_util_log
  xingpong
  DESTINATION libexec)
