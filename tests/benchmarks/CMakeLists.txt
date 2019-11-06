project(libssh-benchmarks C)

set(benchmarks_SRCS
  bench_scp.c bench_sftp bench_raw.c benchmarks.c latency.c
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
)

add_executable(benchmarks ${benchmarks_SRCS})

target_link_libraries(benchmarks ssh::ssh)
