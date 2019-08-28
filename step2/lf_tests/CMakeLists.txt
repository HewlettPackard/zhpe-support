add_executable(atomtest atomtest.c)
target_link_libraries(atomtest PUBLIC zhpeq_util_fab zhpeq)

add_executable(burst burst.c)
target_link_libraries(burst PUBLIC zhpeq_util_fab)

add_executable(famtest famtest.c)
target_link_libraries(famtest PUBLIC zhpeq_util_fab)

add_executable(gettest gettest.c)
target_link_libraries(gettest PUBLIC zhpeq_util_fab)

add_executable(mmaptest mmaptest.c)
target_link_libraries(mmaptest PUBLIC zhpeq_util_fab)

add_executable(regtest regtest.c)
target_link_libraries(regtest PUBLIC zhpeq_util_fab zhpe_stats)

add_executable(ringpong ringpong.c)
target_link_libraries(ringpong PUBLIC zhpeq_util_fab)

install(
  TARGETS atomtest burst famtest gettest mmaptest regtest ringpong
  DESTINATION libexec)
