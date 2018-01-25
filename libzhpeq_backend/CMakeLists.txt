add_compile_options(-fvisibility=hidden)
add_library(zhpeq_backend SHARED backend.c backend_libfabric.c)
target_link_libraries(zhpeq_backend PUBLIC zhpeq_util zhpeq_util_fab fabric)

install(TARGETS zhpeq_backend DESTINATION lib)
