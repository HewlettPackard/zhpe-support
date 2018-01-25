add_executable(ringpong ringpong.c)
target_link_libraries(ringpong zhpeq zhpeq_util zhpeq_util_fab fabric)

install(TARGETS ringpong DESTINATION libexec)
