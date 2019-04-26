add_executable(burst burst.c)
target_link_libraries(burst PUBLIC zhpeq_util_fab)

add_executable(famtest famtest.c)
target_link_libraries(famtest PUBLIC zhpeq_util_fab)

add_executable(gettest gettest.c)
target_link_libraries(gettest PUBLIC zhpeq_util_fab)

add_executable(regtest regtest.c)
target_link_libraries(regtest PUBLIC zhpeq_util_fab zhpe_stats)

add_executable(ringpong ringpong.c)
target_link_libraries(ringpong PUBLIC zhpeq_util_fab)

install(
  TARGETS burst famtest gettest regtest ringpong
  DESTINATION libexec)
