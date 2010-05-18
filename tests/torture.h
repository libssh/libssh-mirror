#ifndef _TORTURE_H
#define _TORTURE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <check.h>

/* Used by main to communicate with parse_opt. */
struct argument_s {
  char *args[2];
  int nofork;
  int verbose;
};

void torture_cmdline_parse(int argc, char **argv, struct argument_s *arguments);

/* create_case() with timeout of 30seconds (default) */
void torture_create_case(Suite *s, const char *name, TFun function);

/* create_case() with timeout of 30seconds (default) and fixture */
void torture_create_case_fixture(Suite *s, const char *name, TFun function,
    void (*setup)(void), void (*teardown)(void));

/*
 * create_case_timeout() allow to specific a specific timeout - intended for
 * breaking testcases which needs longer then 30seconds (default)
 */
void torture_create_case_timeout(Suite *s, const char *name, TFun function,
    int timeout);

/*
 * returns the verbosity level asked by user
 */
int torture_libssh_verbosity(void);


/*
 * This function must be defined in every unit test file.
 */
Suite *torture_make_suite(void);


#endif /* _TORTURE_H */
