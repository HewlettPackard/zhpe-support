add_library(zhpe_stats SHARED libzhpe_stats.c)
target_link_libraries(zhpe_stats PUBLIC zhpeq_util simh -lm)
# cmake v3.13 or later: target_link_options(zhpe_stats PRIVATE -znow)
set_target_properties(zhpe_stats PROPERTIES LINK_FLAGS -znow)
if (ZSTA)
   add_compile_definitions(HAVE_ZHPE_STATS)
endif(ZSTA)

install(TARGETS zhpe_stats DESTINATION lib)
install(FILES
  ${CMAKE_SOURCE_DIR}/include/zhpe_stats.h
  ${CMAKE_SOURCE_DIR}/include/zhpe_stats_types.h
  DESTINATION include)
install(PROGRAMS extract_overheads.sh matchem.awk stats_unpack.sh unpackdata.py DESTINATION libexec/zhpe_stats)
