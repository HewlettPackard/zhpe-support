add_library(zhpeq_util_fab SHARED libzhpeq_util_fab.c)
target_link_libraries(
  zhpeq_util_fab PUBLIC fabric zhpeq_util Threads::Threads)

install(TARGETS zhpeq_util_fab DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_util_fab.h DESTINATION include)
