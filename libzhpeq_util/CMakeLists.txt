add_compile_options(-fPIC)
add_library(zhpeq_util STATIC libzhpeq_util.c)

#install(TARGETS zhpeq_util DESTINATION lib)
#install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_util.h DESTINATION include)

