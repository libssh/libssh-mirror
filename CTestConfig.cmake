set(UPDATE_TYPE "true")

set(MEMORYCHECK_SUPPRESSIONS_FILE ${CMAKE_SOURCE_DIR}/tests/valgrind.supp)
#set(CTEST_CUSTOM_MEMCHECK_IGNORE torture_rand)

set(CTEST_PROJECT_NAME "libssh")
set(CTEST_NIGHTLY_START_TIME "01:00:00 CET")

set(CTEST_DROP_METHOD "http")
set(CTEST_DROP_SITE "test.libssh.org")
set(CTEST_DROP_LOCATION "/submit.php?project=libssh")
set(CTEST_DROP_SITE_CDASH TRUE)
