add_executable(edgetest edgetest.c)
target_link_libraries(edgetest PRIVATE zhpeq zhpeq_util)
add_executable(libzhpeq_ld libzhpeq_ld.c)
target_link_libraries(libzhpeq_ld PRIVATE zhpeq)
add_executable(libzhpeq_util_log libzhpeq_util_log.c)
target_link_libraries(libzhpeq_util_log PRIVATE zhpeq_util)
add_executable(libzhpeq_qalloc libzhpeq_qalloc.c)
target_link_libraries(libzhpeq_qalloc PRIVATE zhpeq zhpeq_util)
add_executable(libzhpeq_qattr libzhpeq_qattr.c)
target_link_libraries(libzhpeq_qattr PRIVATE zhpeq zhpeq_util)
add_executable(libzhpeq_regtime libzhpeq_regtime.c)
target_link_libraries(libzhpeq_regtime PRIVATE zhpeq zhpeq_util)
add_executable(xingpong xingpong.c)
Target_link_libraries(xingpong PRIVATE zhpeq zhpeq_util)
install(
  TARGETS
  edgetest
  libzhpeq_ld
  libzhpeq_qalloc
  libzhpeq_qattr
  libzhpeq_regtime
  libzhpeq_util_log
  xingpong
  DESTINATION libexec)
