/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#ifndef OPTIONS_H_
#define OPTIONS_H_

struct ssh_options_struct {
    struct error_struct error;
    char *banner; /* explicit banner to send */
    char *username;
    char *host;
    char *bindaddr;
    int bindport;
    char *identity;
    char *ssh_dir;
    char *known_hosts_file;
    socket_t fd; /* specificaly wanted file descriptor, don't connect host */
    int port;
    int dont_verify_hostkey; /* Don't spare time, don't check host key ! unneeded to say it's dangerous and not safe */
    int use_nonexisting_algo; /* if user sets a not supported algorithm for kex, don't complain */
    char *wanted_methods[10]; /* the kex methods can be choosed. better use the kex fonctions to do that */
    void *wanted_cookie; /* wants a specific cookie to be sent ? if null, generate a new one */
    ssh_callbacks callbacks; /* Callbacks to user functions */
    long timeout; /* seconds */
    long timeout_usec;
    int ssh2allowed;
    int ssh1allowed;
    char *dsakey;
    char *rsakey; /* host key for server implementation */
    int log_verbosity;

};

#endif /* OPTIONS_H_ */
