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

ssh_session session;

static void setup(void) {
    session = ssh_new();
}

static void teardown(void) {
    ssh_free(session);
}

static void test_algorithm(const char *algo) {
  int rc;
  ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
  rc=ssh_options_set(session,SSH_OPTIONS_CIPHERS_C_S,algo);
  ck_assert_msg(rc==SSH_OK,ssh_get_error(session));
  rc=ssh_options_set(session,SSH_OPTIONS_CIPHERS_S_C,algo);
  ck_assert_msg(rc==SSH_OK,ssh_get_error(session));
  rc=ssh_connect(session);
  ck_assert_msg(rc==SSH_OK,ssh_get_error(session));
  rc=ssh_userauth_none(session,NULL);
  if(rc != SSH_OK){
    rc=ssh_get_error_code(session);
    ck_assert_msg(rc==SSH_REQUEST_DENIED,ssh_get_error(session));
  }
  ssh_disconnect(session);
}

START_TEST (torture_algorithms_aes128_cbc)
{
  test_algorithm("aes128-cbc");
}
END_TEST

START_TEST (torture_algorithms_aes192_cbc)
{
  test_algorithm("aes192-cbc");
}
END_TEST

START_TEST (torture_algorithms_aes256_cbc)
{
  test_algorithm("aes256-cbc");
}
END_TEST

START_TEST (torture_algorithms_aes128_ctr)
{
  test_algorithm("aes128-ctr");
}
END_TEST

START_TEST (torture_algorithms_aes192_ctr)
{
  test_algorithm("aes192-ctr");
}
END_TEST

START_TEST (torture_algorithms_aes256_ctr)
{
  test_algorithm("aes256-ctr");
}
END_TEST

START_TEST (torture_algorithms_3des_cbc)
{
  test_algorithm("3des-cbc");
}
END_TEST

START_TEST (torture_algorithms_blowfish_cbc)
{
  test_algorithm("blowfish-cbc");
}
END_TEST

static Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_algorithms");

  torture_create_case_fixture(s, "torture_algorithms_aes128-cbc",
          torture_algorithms_aes128_cbc, setup, teardown);
  torture_create_case_fixture(s, "torture_algorithms_aes192-cbc",
          torture_algorithms_aes192_cbc, setup, teardown);
   torture_create_case_fixture(s, "torture_algorithms_aes256-cbc",
          torture_algorithms_aes256_cbc, setup, teardown);
   torture_create_case_fixture(s, "torture_algorithms_aes128-ctr",
          torture_algorithms_aes128_ctr, setup, teardown);
   torture_create_case_fixture(s, "torture_algorithms_aes192-ctr",
          torture_algorithms_aes192_ctr, setup, teardown);
    torture_create_case_fixture(s, "torture_algorithms_aes256-ctr",
          torture_algorithms_aes256_ctr, setup, teardown);
    torture_create_case_fixture(s, "torture_algorithms_3des-cbc",
          torture_algorithms_3des_cbc, setup, teardown);
    torture_create_case_fixture(s, "torture_algorithms_blowfish-cbc",
          torture_algorithms_blowfish_cbc, setup, teardown);
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
