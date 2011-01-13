#include "torture.h"

#include <stdio.h>

static int verbosity = 0;

int torture_libssh_verbosity(void){
  return verbosity;
}

int main(int argc, char **argv) {
  struct argument_s arguments;

  arguments.verbose=0;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;

  return torture_run_tests();
}
