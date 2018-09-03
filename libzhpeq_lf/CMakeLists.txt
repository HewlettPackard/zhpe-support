add_library(zhpeq_lf SHARED zhpeq_lf.c)
target_link_libraries(zhpeq_lf PRIVATE zhpeq_util PUBLIC fabric)

install(TARGETS zhpeq_lf DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/include/zhpeq_lf.h DESTINATION include)
