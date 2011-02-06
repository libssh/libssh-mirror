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

#include "libssh/priv.h"

/* Used by main to communicate with parse_opt. */
struct argument_s {
  char *args[2];
  int verbose;
};

void torture_cmdline_parse(int argc, char **argv, struct argument_s *arguments);

/*
 * Returns the verbosity level asked by user
 */
int torture_libssh_verbosity(void);

ssh_session torture_ssh_session(const char *host,
                                const char *user,
                                const char *password);

/*
 * This function must be defined in every unit test file.
 */
int torture_run_tests(void);

#endif /* _TORTURE_H */
