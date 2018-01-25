add_executable(zhpe_helper zhpe_helper.c)
target_link_libraries(zhpe_helper zhpeq_util)

install(TARGETS zhpe_helper DESTINATION bin)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/driver/zhpe.ko
    COMMAND ${CMAKE_SOURCE_DIR}/driver/build.sh ${CMAKE_BINARY_DIR}/driver
    DEPENDS
    ${CMAKE_SOURCE_DIR}/driver/build.sh
    ${CMAKE_SOURCE_DIR}/driver/Makefile
    ${CMAKE_SOURCE_DIR}/driver/zhpe.c
    ${CMAKE_SOURCE_DIR}/include/zhpe.h
    ${CMAKE_SOURCE_DIR}/include/zhpeq.h
)
add_custom_target(driver ALL DEPENDS ${CMAKE_BINARY_DIR}/driver/zhpe.ko)

install(FILES ${CMAKE_BINARY_DIR}/driver/zhpe.ko DESTINATION lib/modules)

