#include "torture.h"

#include <stdio.h>

static int verbosity = 0;

int torture_libssh_verbosity(void){
  return verbosity;
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;

    return torture_run_tests();
}
