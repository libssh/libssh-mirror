/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
ssh_session session;

#define KNOWNHOSTFILES "libssh_torture_knownhosts"

static void setup(void) {
    session = ssh_new();
}

static void teardown(void) {
    ssh_free(session);
    unlink(KNOWNHOSTFILES);
}

START_TEST (torture_knownhosts_port)
{
  int rc;
  char buffer[200];
  FILE *file;
  /* Connect to localhost:22, force the port to 1234 and then write
   * the known hosts file. Then check that the entry written is
   * [localhost]:1234
   */
  ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
  ssh_options_set(session,SSH_OPTIONS_KNOWNHOSTS,KNOWNHOSTFILES);
  rc=ssh_connect(session);
  ck_assert_int_eq(rc,SSH_OK);
  session->port=1234;
  rc=ssh_write_knownhost(session);
  ck_assert_int_eq(rc,SSH_OK);
  ssh_disconnect(session);
  ssh_free(session);
  file=fopen(KNOWNHOSTFILES,"r");
  ck_assert(file != NULL);
  fgets(buffer,sizeof(buffer),file);
  buffer[sizeof(buffer)-1]='\0';
  ck_assert(strstr(buffer,"[localhost]:1234 ") != NULL);
  fclose(file);

  /* now, connect back to the ssh server and verify the known host line */
  session=ssh_new();
  ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
  ssh_options_set(session,SSH_OPTIONS_KNOWNHOSTS,KNOWNHOSTFILES);
  rc=ssh_connect(session);
  ck_assert_int_eq(rc,SSH_OK);
  session->port=1234;
  rc=ssh_is_server_known(session);
  ck_assert_int_eq(rc,SSH_SERVER_KNOWN_OK);
  ssh_disconnect(session);
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_knownhosts");

  torture_create_case_fixture(s, "torture_knownhosts_port",
          torture_knownhosts_port, setup, teardown);
  return s;
}

int main(int argc, char **argv) {
  Suite *s = NULL;
  SRunner *sr = NULL;
  struct argument_s arguments;
  int nf;

  ZERO_STRUCT(arguments);

  torture_cmdline_parse(argc, argv, &arguments);

  s = torture_make_suite();

  sr = srunner_create(s);
  if (arguments.nofork) {
    srunner_set_fork_status(sr, CK_NOFORK);
  }
  srunner_run_all(sr, CK_VERBOSE);
  nf = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
