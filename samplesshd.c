/* sshd.c */
/* yet another ssh daemon (Yawn!) */
/*
Copyright 2004 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <unistd.h>
int main(int argc, char **argv){
    SSH_OPTIONS *options=ssh_options_new();
    SSH_SESSION *session;
    SSH_BIND *ssh_bind;
    SSH_MESSAGE *message;
    ssh_options_getopt(options,&argc,argv);
    ssh_options_set_dsa_server_key(options,"/etc/ssh/ssh_host_dsa_key");
    ssh_options_set_rsa_server_key(options,"/etc/ssh/ssh_host_rsa_key");
    ssh_bind=ssh_bind_new();
    ssh_bind_set_options(ssh_bind,options);
    if(ssh_bind_listen(ssh_bind)<0){
        printf("Error listening to socket: %s\n",ssh_get_error(ssh_bind));
        return 1;
    }
    session=ssh_bind_accept(ssh_bind);
    if(!session){
      printf("error accepting a connection : %s\n",ssh_get_error(ssh_bind));
      return 1;
    }
    printf("Socket connecté : %d\n",ssh_get_fd(session));
    if(ssh_accept(session)){
        printf("ssh_accept : %s\n",ssh_get_error(session));
        return 1;
    }
    do {
        message=ssh_message_get(session);
    } while (message);
    printf("error : %s\n",ssh_get_error(session));
    return 0;
}

