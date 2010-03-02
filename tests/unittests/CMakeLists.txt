project(unittests C)

add_check_test(torture_misc torture_misc.c ${TORTURE_LIBRARY})
add_check_test(torture_keyfiles torture_keyfiles.c ${TORTURE_LIBRARY})
