project(unittests C)

add_cmockery_test(torture_buffer torture_buffer.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_callbacks torture_callbacks.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_init torture_init.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_list torture_list.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_misc torture_misc.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_options torture_options.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_isipaddr torture_isipaddr.c ${TORTURE_LIBRARY})
if (UNIX AND NOT WIN32)
    # requires ssh-keygen
    add_cmockery_test(torture_keyfiles torture_keyfiles.c ${TORTURE_LIBRARY})
    # requires pthread
    add_cmockery_test(torture_rand torture_rand.c ${TORTURE_LIBRARY})
endif (UNIX AND NOT WIN32)
