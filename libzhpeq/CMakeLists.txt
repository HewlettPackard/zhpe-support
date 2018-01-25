add_library(zhpeq SHARED libzhpeq.c)
target_link_libraries(zhpeq PRIVATE zhpeq_util PUBLIC dl pthread)

install(TARGETS zhpeq DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq.h DESTINATION include)
