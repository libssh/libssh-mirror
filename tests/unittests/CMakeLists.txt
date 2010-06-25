project(unittests C)

add_check_test(torture_callbacks torture_callbacks.c ${TORTURE_LIBRARY})
add_check_test(torture_init torture_init.c ${TORTURE_LIBRARY})
add_check_test(torture_keyfiles torture_keyfiles.c ${TORTURE_LIBRARY})
add_check_test(torture_knownhosts torture_knownhosts.c ${TORTURE_LIBRARY})
add_check_test(torture_list torture_list.c ${TORTURE_LIBRARY})
add_check_test(torture_misc torture_misc.c ${TORTURE_LIBRARY})
add_check_test(torture_options torture_options.c ${TORTURE_LIBRARY})
