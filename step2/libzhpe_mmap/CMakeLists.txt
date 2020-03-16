add_compile_options(-D_ZHPEQ_TEST_COMPAT_)
add_library(zhpe_mmap SHARED libzhpe_mmap.c)

target_link_libraries(zhpe_mmap PUBLIC zhpeq_util zhpeq_util_fab)

install(TARGETS zhpe_mmap DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpe_mmap.h DESTINATION include)
