add_library(zhpe_stats INTERFACE)
set(ZSTA_LIB ${LIBD}/lib/libzhpe_stats.so)
target_link_libraries(zhpe_stats INTERFACE ${ZSTA_LIB})
if (ZSTA)
  message("ZSTA_LIB " ${ZSTA_LIB})
  target_compile_definitions(zhpe_stats INTERFACE HAVE_ZHPE_STATS)
endif(ZSTA)

