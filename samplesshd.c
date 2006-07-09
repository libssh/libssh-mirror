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
#include <string.h>
#include <stdio.h>

int auth_password(char *user, char *password){
    if(strcmp(user,"aris"))
        return 0;
    if(strcmp(password,"lala"))
        return 0;
    return 1; // authenticated 
}

int main(int argc, char **argv){
    SSH_OPTIONS *options=ssh_options_new();
    SSH_SESSION *session;
    SSH_BIND *ssh_bind;
    SSH_MESSAGE *message;
    CHANNEL *chan=0;
    int auth=0;
    int sftp=0;
    int i;
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
        if(!message)
            break;
        switch(ssh_message_type(message)){
            case SSH_AUTH_REQUEST:
                switch(ssh_message_subtype(message)){
                    case SSH_AUTH_PASSWORD:
                        printf("User %s wants to auth with pass %s\n",
                               ssh_message_auth_user(message),
                               ssh_message_auth_password(message));
                        if(auth_password(ssh_message_auth_user(message),
                           ssh_message_auth_password(message))){
                               auth=1;
                               ssh_message_auth_reply_success(message,0);
                               break;
                           }
                        // not authenticated, send default message
                    case SSH_AUTH_NONE:
                    default:
                        ssh_message_auth_set_methods(message,SSH_AUTH_PASSWORD);
                        ssh_message_reply_default(message);
                        break;
                }
                break;
            default:
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (!auth);
    if(!auth){
        printf("error : %s\n",ssh_get_error(session));
	ssh_finalize();
        return 1;
    }
    do {
        message=ssh_message_get(session);
        if(message){
            switch(ssh_message_type(message)){
                case SSH_CHANNEL_REQUEST_OPEN:
                    if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION){
                        chan=ssh_message_channel_request_open_reply_accept(message);
                        break;
                    }
                default:
                ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }
    } while(message && !chan);
    if(!chan){
        printf("error : %s\n",ssh_get_error(session));
	ssh_finalize();
        return 1;
    }
    do {
        message=ssh_message_get(session);
        if(message && ssh_message_type(message)==SSH_CHANNEL_REQUEST && 
           ssh_message_subtype(message)==SSH_CHANNEL_REQUEST_SHELL){
//            if(!strcmp(ssh_message_channel_request_subsystem(message),"sftp")){
                sftp=1;
                ssh_message_channel_request_reply_success(message);
                break;
 //           }
           }
        if(!sftp){
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (message && !sftp);
    if(!sftp){
        printf("error : %s\n",ssh_get_error(session));
        return 1;
    }
    printf("it works !\n");
    BUFFER *buf=buffer_new();
    do{
        i=channel_read(chan,buf,0,0);
        if(i>0)
            write(1,buffer_get(buf),buffer_get_len(buf));
    } while (i>0);
    ssh_disconnect(session);
    ssh_finalize();
    return 0;
}

