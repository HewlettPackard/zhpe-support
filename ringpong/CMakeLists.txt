add_executable(gettest gettest.c)
target_link_libraries(gettest zhpeq zhpeq_util zhpeq_util_fab fabric)
add_executable(ringpong ringpong.c)
target_link_libraries(ringpong zhpeq zhpeq_util zhpeq_util_fab fabric)

install(
  TARGETS
  gettest
  ringpong
  DESTINATION libexec)
