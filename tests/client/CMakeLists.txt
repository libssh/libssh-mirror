project(clienttests C)

add_cmockery_test(torture_algorithms torture_algorithms.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_auth torture_auth.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_knownhosts torture_knownhosts.c ${TORTURE_LIBRARY})
add_cmockery_test(torture_proxycommand torture_proxycommand.c ${TORTURE_LIBRARY})
