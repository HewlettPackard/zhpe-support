add_compile_options(-mcx16 -mclflushopt -mclwb)
add_library(zhpeq_util SHARED libzhpeq_util.c)
target_link_libraries(zhpeq_util PUBLIC atomic uuid Threads::Threads)

install(TARGETS zhpeq_util DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_util.h DESTINATION include)
