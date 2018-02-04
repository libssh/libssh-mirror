project(fuzzing CXX)

find_package(ClangFuzzer)

add_executable(ssh_server_fuzzer ssh_server_fuzzer.cpp)
target_link_libraries(ssh_server_fuzzer
    ${CLANG_FUZZER_LIBRARY}
    ${LIBSSH_THREADS_STATIC_LIBRARY}
    ${LIBSSH_THREADS_LINK_LIBRARIES})
