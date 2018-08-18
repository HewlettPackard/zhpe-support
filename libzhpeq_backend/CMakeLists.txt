add_compile_options(-fvisibility=hidden)
add_library(
  zhpeq_backend SHARED
  backend.c
  backend_libfabric.c
  backend_zhpe.c)
target_link_libraries(
  zhpeq_backend PUBLIC
  zhpeq_util
  zhpeq_util_fab
  fabric
  uuid)

install(TARGETS zhpeq_backend DESTINATION lib)
