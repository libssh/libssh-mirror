#ifndef _TORTURE_H
#define _TORTURE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <google/cmockery.h>

/*
 * Returns the verbosity level asked by user
 */
int torture_libssh_verbosity(void);


/*
 * This function must be defined in every unit test file.
 */
int torture_run_tests(void);

#endif /* _TORTURE_H */
