add_compile_options(-D_ZHPEQ_TEST_COMPAT_)

add_executable(atomtest atomtest.c)
target_link_libraries(atomtest PUBLIC zhpeq_util_fab zhpeq)

add_executable(burst burst.c)
target_link_libraries(burst PUBLIC zhpeq_util_fab)

add_executable(famatom famatom.c)
target_link_libraries(famatom PUBLIC zhpeq_util_fab)

add_executable(famtest famtest.c)
target_link_libraries(famtest PUBLIC zhpeq_util_fab)

add_executable(gettest gettest.c)
target_link_libraries(gettest PUBLIC zhpeq_util_fab)

add_executable(mmapspeed mmapspeed.c)
target_link_libraries(mmapspeed PUBLIC zhpeq_util_fab)

add_executable(mmaptest mmaptest.c)
target_link_libraries(mmaptest PUBLIC zhpeq_util_fab)

add_executable(onenode_mmaptest onenode_mmaptest.c)
target_link_libraries(onenode_mmaptest PUBLIC zhpeq_util_fab zhpe_mmap)

add_executable(regtest regtest.c)
target_link_libraries(regtest PUBLIC zhpe_stats zhpeq_util_fab)

add_executable(ringpong ringpong.c)
target_link_libraries(ringpong PUBLIC zhpeq_util_fab)

install(
  TARGETS
  atomtest
  burst
#  famatom
  famtest
  gettest
  mmapspeed
  mmaptest
  onenode_mmaptest
  regtest
  ringpong
  DESTINATION libexec)
