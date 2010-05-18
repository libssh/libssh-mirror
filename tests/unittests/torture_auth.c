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

static void setup(void) {
  int verbosity=torture_libssh_verbosity();
  session = ssh_new();
  ssh_options_set(session,SSH_OPTIONS_HOST,"localhost");
  ssh_options_set(session,SSH_OPTIONS_LOG_VERBOSITY,&verbosity);
}

static void teardown(void) {
  ssh_disconnect(session);
  ssh_free(session);
}

START_TEST (torture_auth_kbdint)
{
  int rc;
  char *user=getenv("TORTURE_USER");
  char *password=getenv("TORTURE_PASSWORD");
  ck_assert_msg(user != NULL, "Please set the environment variable TORTURE_USER"
      " to enable this test");
  ck_assert_msg(password != NULL, "Please set the environment variable "
      "TORTURE_PASSWORD to enable this test");
  ssh_options_set(session,SSH_OPTIONS_USER,user);
  rc=ssh_connect(session);
  ck_assert_msg(rc==SSH_OK,ssh_get_error(session));

  rc=ssh_userauth_none(session,NULL);
  /* This request should return a SSH_REQUEST_DENIED error */
  if(rc == SSH_ERROR){
    ck_assert_msg(ssh_get_error_code(session)==SSH_REQUEST_DENIED,
        ssh_get_error(session));
  }
  ck_assert_msg(ssh_auth_list(session) & SSH_AUTH_METHOD_INTERACTIVE,
      "SSH server doesn't allow keyboard-interactive");
  rc=ssh_userauth_kbdint(session,NULL,NULL);
  ck_assert_msg(rc==SSH_AUTH_INFO,ssh_get_error(session));
  ck_assert_int_eq(ssh_userauth_kbdint_getnprompts(session),1);
  ssh_userauth_kbdint_setanswer(session,0,password);
  rc=ssh_userauth_kbdint(session,NULL,NULL);
  ck_assert_msg(rc==SSH_AUTH_SUCCESS,ssh_get_error(session));

}
END_TEST

START_TEST (torture_auth_password)
{
  int rc;
  char *user=getenv("TORTURE_USER");
  char *password=getenv("TORTURE_PASSWORD");
  ck_assert_msg(user != NULL, "Please set the environment variable TORTURE_USER"
      " to enable this test");
  ck_assert_msg(password != NULL, "Please set the environment variable "
      "TORTURE_PASSWORD to enable this test");
  ssh_options_set(session,SSH_OPTIONS_USER,user);
  rc=ssh_connect(session);
  ck_assert_msg(rc==SSH_OK,ssh_get_error(session));

  rc=ssh_userauth_none(session,NULL);
  /* This request should return a SSH_REQUEST_DENIED error */
  if(rc == SSH_ERROR){
    ck_assert_msg(ssh_get_error_code(session)==SSH_REQUEST_DENIED,
        ssh_get_error(session));
  }
  ck_assert_msg(ssh_auth_list(session) & SSH_AUTH_METHOD_INTERACTIVE,
      "SSH server doesn't allow keyboard-interactive");
  rc=ssh_userauth_password(session,NULL,password);
  ck_assert_msg(rc==SSH_AUTH_SUCCESS,ssh_get_error(session));
}
END_TEST

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_auth");

  torture_create_case_fixture(s, "torture_auth_kbint",
      torture_auth_kbdint, setup, teardown);
  torture_create_case_fixture(s, "torture_auth_password",
        torture_auth_password, setup, teardown);
  return s;
}

