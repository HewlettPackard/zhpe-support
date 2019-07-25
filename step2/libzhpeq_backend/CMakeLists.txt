add_compile_options(-fvisibility=hidden)

add_library(
  zhpeq_backend
  SHARED backend.c backend_libfabric.c backend_zhpe.c)
target_link_libraries(
  zhpeq_backend
  PRIVATE zhpeq_util_fab zhpeq_util
  PUBLIC numa uuid Threads::Threads)

install(TARGETS zhpeq_backend DESTINATION lib)
