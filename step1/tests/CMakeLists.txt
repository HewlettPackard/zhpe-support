add_compile_options(-D_ZHPEQ_TEST_COMPAT_)

add_executable(edgetest edgetest.c)
target_link_libraries(edgetest PUBLIC zhpeq zhpeq_util)

add_executable(enqapong enqapong.c)
target_link_libraries(enqapong PUBLIC zhpeq zhpeq_util)

add_executable(enqatest enqatest.c)
target_link_libraries(enqatest PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_ld libzhpeq_ld.c)
target_link_libraries(libzhpeq_ld PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_mr libzhpeq_mr.c)
target_link_libraries(libzhpeq_mr PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_pcitime libzhpeq_pcitime.c)
target_link_libraries(libzhpeq_pcitime PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_qalloc libzhpeq_qalloc.c)
target_link_libraries(libzhpeq_qalloc PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_qattr libzhpeq_qattr.c)
target_link_libraries(libzhpeq_qattr PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_regtime libzhpeq_regtime.c)
target_link_libraries(libzhpeq_regtime PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_util_log libzhpeq_util_log.c)
target_link_libraries(libzhpeq_util_log PUBLIC zhpeq_util)

add_executable(libzhpeq_zaddr libzhpeq_zaddr.c)
target_link_libraries(libzhpeq_zaddr PUBLIC zhpeq zhpeq_util)

add_executable(nop nop.c)
target_link_libraries(nop PUBLIC zhpeq zhpeq_util)

add_executable(xingpong xingpong.c)
target_link_libraries(xingpong PUBLIC zhpeq zhpeq_util)

install(
  TARGETS
  edgetest
  enqapong
  enqatest
  libzhpeq_ld
  libzhpeq_zaddr
  libzhpeq_mr
  libzhpeq_pcitime
  libzhpeq_qalloc
  libzhpeq_qattr
  libzhpeq_regtime
  libzhpeq_util_log
  nop
  xingpong
  DESTINATION libexec)
