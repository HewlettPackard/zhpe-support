add_compile_options(-DZHPEQ_DIRECT)
add_library(zhpeq SHARED libzhpeq.c)
target_link_libraries(
  zhpeq PUBLIC numa uuid jansson zhpe_stats zhpeq_util dl Threads::Threads)
if (ZSTA)
  target_compile_definitions(zhpeq PUBLIC HAVE_ZHPE_STATS)
endif(ZSTA)

install(TARGETS zhpeq DESTINATION lib)
install(
  FILES
  ${CMAKE_SOURCE_DIR}/include/zhpeq.h
  ${CMAKE_SOURCE_DIR}/asic/include/zhpe_uapi.h
  ${CMAKE_SOURCE_DIR}/asic/include/zhpe_externc.h
  DESTINATION include
)
