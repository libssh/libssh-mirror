#include "torture.h"

#include <stdio.h>

static int verbosity = 0;

static int torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (password && strstr(prompt, "Password:")) {
        if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
            return SSH_AUTH_ERROR;
        }
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);

    return err;
}

int torture_libssh_verbosity(void){
  return verbosity;
}

ssh_session torture_ssh_session(const char *host,
                                const char *user,
                                const char *password) {
    ssh_session session;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    if (password != NULL) {
        int err = torture_auth_kbdint(session, password);
        if (err == SSH_AUTH_ERROR) {
            goto failed;
        }
    } else {
        int err = ssh_userauth_autopubkey(session, NULL);
        if (err == SSH_AUTH_ERROR) {
            goto failed;
        }
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

int main(int argc, char **argv) {
  struct argument_s arguments;

  arguments.verbose=0;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;

  return torture_run_tests();
}

/* vim: set ts=4 sw=4 et cindent syntax=c.doxygen: */
