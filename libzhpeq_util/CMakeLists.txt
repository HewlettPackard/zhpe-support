add_compile_options(-fPIC)
add_library(zhpeq_util STATIC libzhpeq_util.c)
target_link_libraries(zhpeq_util PUBLIC uuid)
