add_executable(edgetest edgetest.c)
target_link_libraries(edgetest PRIVATE zhpeq)
add_executable(libzhpeq_ld libzhpeq_ld.c)
target_link_libraries(libzhpeq_ld PRIVATE zhpeq)
add_executable(libzhpeq_qalloc libzhpeq_qalloc.c)
target_link_libraries(libzhpeq_qalloc PRIVATE zhpeq)
add_executable(libzhpeq_mr libzhpeq_mr.c)
target_link_libraries(libzhpeq_mr PRIVATE zhpeq)
add_executable(libzhpeq_qattr libzhpeq_qattr.c)
target_link_libraries(libzhpeq_qattr PRIVATE zhpeq)
add_executable(libzhpeq_regtime libzhpeq_regtime.c)
add_executable(libzhpeq_util_log libzhpeq_util_log.c)
target_link_libraries(libzhpeq_util_log PRIVATE zhpeq_util)
target_link_libraries(libzhpeq_regtime PRIVATE zhpeq)
add_executable(xingpong xingpong.c)
Target_link_libraries(xingpong PRIVATE zhpeq)
install(
  TARGETS
  edgetest
  libzhpeq_ld
  libzhpeq_mr
  libzhpeq_qalloc
  libzhpeq_qattr
  libzhpeq_regtime
  libzhpeq_util_log
  xingpong
  DESTINATION libexec)
