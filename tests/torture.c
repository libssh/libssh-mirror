#include <stdio.h>
#include <libssh/libssh.h>

#include "torture.h"

static int verbosity = 0;

int torture_libssh_verbosity(void){
  return verbosity;
}

int main(int argc, char **argv) {
    int rc;

    (void) argc;
    (void) argv;

    ssh_init();

    rc = torture_run_tests();

    ssh_finalize();

    return rc;
}
