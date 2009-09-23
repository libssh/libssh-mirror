/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 Aris Adamantiadis <aris@0xbadc0de.be>
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

/* callback.h
 * This file includes the declarations for the libssh callback mechanism
 */

#ifndef _SSH_CALLBACK_H
#define _SSH_CALLBACK_H

#include "libssh.h"

/**
 * @brief SSH authentication callback.
 *
 * @param prompt        Prompt to be displayed.
 * @param buf           Buffer to save the password. You should null-terminate it.
 * @param len           Length of the buffer.
 * @param echo          Enable or disable the echo of what you type.
 * @param verify        Should the password be verified?
 * @param userdata      Userdata to be passed to the callback function. Useful
 *                      for GUI applications.
 *
 * @return              0 on success, < 0 on error.
 */
typedef int (*ssh_auth_callback) (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata);
typedef void (*ssh_log_callback) (ssh_session session, int priority,
    const char *message, void *userdata);

struct ssh_callbacks_struct {
	size_t size;    /* size of this structure */
	void *userdata; /* User-provided data */
	ssh_auth_callback auth_function; /* this functions will be called if e.g. a keyphrase is needed. */
	ssh_log_callback log_function; //log callback
  void (*connect_status_function)(void *arg, float status); /* status callback function */
};

typedef struct ssh_callbacks_struct * ssh_callbacks;

LIBSSH_API int ssh_options_set_auth_callback(SSH_OPTIONS *opt, ssh_auth_callback cb,
    void *userdata);
LIBSSH_API int ssh_options_set_log_function(SSH_OPTIONS *opt,
    ssh_log_callback cb, void *userdata);
LIBSSH_API int ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)
        (void *arg, float status), void *arg);
#endif /*_SSH_CALLBACK_H */
