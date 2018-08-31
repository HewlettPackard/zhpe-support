add_library(zhpeq_util STATIC libzhpeq_util.c)
target_link_libraries(zhpeq_util PUBLIC uuid)

install(TARGETS zhpeq_util DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_util.h DESTINATION include)
