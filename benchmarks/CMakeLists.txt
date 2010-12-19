project(libssh-benchmarks C)

set(benchmarks_SRCS
  
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
)

add_executable(bench_scp bench_scp.c ${benchmarks_SRCS})

target_link_libraries(bench_scp ${LIBSSH_SHARED_LIBRARY})

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
)

if (WITH_SFTP)
endif (WITH_SFTP)
