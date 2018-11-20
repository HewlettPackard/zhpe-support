add_executable(famtest famtest.c)
target_link_libraries(famtest PRIVATE zhpeq_util_fab)

add_executable(gettest gettest.c)
target_link_libraries(gettest PRIVATE zhpeq_util_fab)

add_executable(ringpong ringpong.c)
target_link_libraries(ringpong PRIVATE zhpeq_util_fab)

install(
  TARGETS famtest gettest ringpong
  DESTINATION libexec)
