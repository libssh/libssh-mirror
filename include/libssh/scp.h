/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LIBSSH_SCP_H
#define _LIBSSH_SCP_H

#include <libssh/libssh.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /** Local client uploads files to the remote side */
    SSH_SCP_WRITE,
    /** Local client downloads files from the remote side */
    SSH_SCP_READ,
    SSH_SCP_RECURSIVE = 0x10
};

enum ssh_scp_request_types {
    /** A new directory is going to be pulled */
    SSH_SCP_REQUEST_NEWDIR = 1,
    /** A new file is going to be pulled */
    SSH_SCP_REQUEST_NEWFILE,
    /** End of requests */
    SSH_SCP_REQUEST_EOF,
    /** End of directory */
    SSH_SCP_REQUEST_ENDDIR,
    /** Warning received */
    SSH_SCP_REQUEST_WARNING
};

typedef struct ssh_scp_struct *ssh_scp;

SSH_DEPRECATED LIBSSH_API int ssh_scp_accept_request(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int ssh_scp_close(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int ssh_scp_deny_request(ssh_scp scp,
                                                   const char *reason);
SSH_DEPRECATED LIBSSH_API void ssh_scp_free(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int ssh_scp_init(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int ssh_scp_leave_directory(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API ssh_scp ssh_scp_new(ssh_session session,
                                              int mode,
                                              const char *location);
SSH_DEPRECATED LIBSSH_API int ssh_scp_pull_request(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int
ssh_scp_push_directory(ssh_scp scp, const char *dirname, int mode);
SSH_DEPRECATED LIBSSH_API int
ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, int perms);
SSH_DEPRECATED LIBSSH_API int ssh_scp_push_file64(ssh_scp scp,
                                                  const char *filename,
                                                  uint64_t size,
                                                  int perms);
SSH_DEPRECATED LIBSSH_API int
ssh_scp_read(ssh_scp scp, void *buffer, size_t size);
SSH_DEPRECATED LIBSSH_API const char *ssh_scp_request_get_filename(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int ssh_scp_request_get_permissions(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API size_t ssh_scp_request_get_size(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API uint64_t ssh_scp_request_get_size64(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API const char *ssh_scp_request_get_warning(ssh_scp scp);
SSH_DEPRECATED LIBSSH_API int
ssh_scp_write(ssh_scp scp, const void *buffer, size_t len);
SSH_DEPRECATED LIBSSH_API int ssh_scp_is_closed(ssh_scp scp);

#ifdef __cplusplus
}
#endif

#endif /* _LIBSSH_SCP_H */
