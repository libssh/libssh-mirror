/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

static int auth_password(char *user, char *password){
    if(strcmp(user,"aris"))
        return 0;
    if(strcmp(password,"lala"))
        return 0;
    return 1; // authenticated
}

int main(int argc, char **argv){
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    ssh_channel chan=0;
    ssh_buffer buf;
    int auth=0;
    int sftp=0;
    int i;
    int r;

    sshbind=ssh_bind_new();
    session=ssh_new();
    ssh_options_getopt(session,&argc,argv);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

    if(ssh_bind_listen(sshbind)<0){
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }
    r=ssh_bind_accept(sshbind,session);
    if(r==SSH_ERROR){
      printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
      return 1;
    }
    if(ssh_accept(session)){
        printf("ssh_accept: %s\n",ssh_get_error(session));
        return 1;
    }
    do {
        message=ssh_message_get(session);
        if(!message)
            break;
        switch(ssh_message_type(message)){
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message)){
                    case SSH_AUTH_METHOD_PASSWORD:
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
                    case SSH_AUTH_METHOD_NONE:
                    default:
                        ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
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
        printf("auth error: %s\n",ssh_get_error(session));
        ssh_disconnect(session);
        return 1;
    }
    do {
        message=ssh_message_get(session);
        if(message){
            switch(ssh_message_type(message)){
                case SSH_REQUEST_CHANNEL_OPEN:
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
        if(message && ssh_message_type(message)==SSH_REQUEST_CHANNEL &&
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
    buf=buffer_new();
    do{
        i=channel_read_buffer(chan,buf,0,0);
        if(i>0)
            write(1,buffer_get(buf),buffer_get_len(buf));
    } while (i>0);
    buffer_free(buf);
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}

