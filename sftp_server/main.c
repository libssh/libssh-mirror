/* main.c */
/* Core of the sftp server */
/*
Copyright 2005 Aris Adamantiadis

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
#include <libssh/sftp.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "server.h"


CHANNEL *recv_channel(SSH_SESSION *session){
    CHANNEL *chan=NULL;
    SSH_MESSAGE *message;
    int sftp=0;
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
    if(!chan)
        return NULL;
    do {
        message=ssh_message_get(session);
        if(message && ssh_message_type(message)==SSH_CHANNEL_REQUEST && 
           ssh_message_subtype(message)==SSH_CHANNEL_REQUEST_SUBSYSTEM){
            if(!strcmp(ssh_message_channel_request_subsystem(message),"sftp")){
                sftp=1;
                ssh_message_channel_request_reply_success(message);
                break;
            }
           }
           if(!sftp){
               ssh_message_reply_default(message);
           }
           ssh_message_free(message);
    } while (message && !sftp);
    if(!message)
        return NULL;
    return chan;
}

int main(int argc, char **argv){
    SSH_OPTIONS *options=ssh_options_new();
    SSH_SESSION *session;
    SSH_BIND *ssh_bind;
    CHANNEL *chan=NULL;
    SFTP_SESSION *sftp=NULL;
    int ret;
    ssh_options_getopt(options,&argc,argv);
    if(argc>1)
        ret=parse_config(argv[1]);
    else
        ret=parse_config("mercurius.conf");
    if(ret != 0){
        printf("Error parsing configuration file\n");
        return 1;
    }
    if(!rsa && !dsa){
        printf("There must be at least one RSA or DSA host key\n");
        return 1;
    }
    if(dsa)
        ssh_options_set_dsa_server_key(options,dsa);
    if(rsa)
        ssh_options_set_rsa_server_key(options,rsa);
    printf("port : %d\n",port);
    if(port!=0)
        ssh_options_set_port(options,port);
    ssh_bind=ssh_bind_new();
    ssh_bind_set_options(ssh_bind,options);
    if(ssh_bind_listen(ssh_bind)<0){
        printf("Error listening to socket: %s\n",ssh_get_error(ssh_bind));
        return 1;
    }
    signal(SIGCHLD,SIG_IGN);
    while(1){
        session=ssh_bind_accept(ssh_bind);
        if(!session){
            printf("error accepting a connection : %s\n",ssh_get_error(ssh_bind));
            return 1;
        }
        if(fork()==0){
            break;
        }
        ssh_silent_disconnect(session);
    }
    ssh_bind_free(ssh_bind);
    
    printf("Socket connected : %d\n",ssh_get_fd(session));
    if(ssh_accept(session)){
        printf("ssh_accept : %s\n",ssh_get_error(session));
        return 1;
    }
    if(do_auth(session)<0){
        printf("error : %s\n",ssh_get_error(session));
        return 1;
    }
    printf("user authenticated\n");
    chan=recv_channel(session);
    if(!chan){
        printf("error : %s\n",ssh_get_error(session));
        return 1;
    }
    sftp=sftp_server_new(session,chan);
    if(sftp_server_init(sftp)){
        printf("error : %s\n",ssh_get_error(session));
        return 1;
    }
    printf("Sftp session open by client\n");
    sftploop(session,sftp);
    ssh_disconnect(session);
    return 0;
}

