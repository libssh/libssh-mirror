/* userauth.c */
/* handle the authentication of the client */
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
//#include <libssh/sftp.h>
#include <security/pam_appl.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include "server.h"

#define SERVICE "sftp"

char *user_password;
int password_conv(int num_msg, const struct pam_message **msg,
                  struct pam_response **resp, void *appdata)
{
    int i=0;
    for(i=0;i<num_msg;++i){
        resp[i]=malloc(sizeof (struct pam_response));
        resp[i]->resp_retcode=0;
        switch(msg[i]->msg_style){
            case PAM_PROMPT_ECHO_ON:
                //printf("PAM: %s",msg[i]->msg);
                resp[i]->resp=strdup(user_password);
                break;
            case PAM_PROMPT_ECHO_OFF:
                //printf("PAM: %s",msg[i]->msg);
                resp[i]->resp=strdup(user_password);
                break;
            case PAM_ERROR_MSG:
                //printf("PAM_ERROR: %s",msg[i]->msg);
                break;
            case PAM_TEXT_INFO:
                //printf("PAM TEXT: %s",msg[i]->msg);
                break;
            default:
                break;
        }
    }
    return PAM_SUCCESS;
}

/* postauth_conf returns -1 on error, else 0 */
int postauth_conf(char *user){
    /* first, find a chroot if any */
    char *root,*ptr;
    char *char_uid;
    char buffer[256];
    int uid;
    struct passwd *pw=getpwnam(user);
    root=user_chroot(user);
    if(root){
        if((ptr=strstr(root,"$HOME"))){
            if(!pw){
                ssh_say(1,"Postauth failed : no home directory for user %s\n",user);
                return -1; // this user has no user directory
            }
            *ptr=0;
            snprintf(buffer,sizeof(buffer),"%s%s/%s",
                     root,pw->pw_dir,ptr+strlen("$HOME"));
        }
        else 
            snprintf(buffer,sizeof(buffer),"%s",root);
    }
    /* we don't chroot right now because we still need getpwnam() */
    char_uid=user_uid(user);
    if(!char_uid){
        if(!pw){
            ssh_say(1,"postauth failed : user %s doesn't exist(try to set the uid setting)\n",user);
            return -1; // user doesn't exist !
        }
        char_uid=user;
    }
    uid=atoi(char_uid);
    if(uid==0 && char_uid[0]!=0){
        pw=getpwnam(char_uid);
        if(!pw){
            ssh_say(1,"postauth failed : user %s does not exist\n",char_uid);
            return -1;
        }
        uid=pw->pw_uid;
    }
    if(root && chroot(buffer)){
        ssh_say(1,"Postauth failed : chroot failed (%s)\n",strerror(errno));
        return -1; // cannot chroot
    }
    if(root){
        chdir("/");
    } else {
        if(pw)
            chdir(pw->pw_dir);
        else
            chdir("/");
    }
    if(setuid(uid)){
        ssh_say(1,"Postauth failed : cannot set uid (%)\n",strerror(errno));
        return -1; // cannot setuid
    }
    return 0;
}
    

struct pam_conv pam_conv ={ password_conv, NULL };
/* returns 1 if authenticated, 0 if failed,
 -1 if you must leave */
int auth_password(char *user, char *password){
    pam_handle_t *pamh;
    int ret;
    static int tries=0;
    if(tries>3)
        return -1;
    tries++;
    user_password=password;
    ret=pam_start(SERVICE,user,&pam_conv,&pamh);
    if(ret==PAM_SUCCESS)
        ret=pam_authenticate(pamh,0);
    if(ret==PAM_SUCCESS)
        ret=pam_acct_mgmt(pamh,0);
    memset(password,0,strlen(password));
    if(ret==PAM_SUCCESS){
        pam_end(pamh,PAM_SUCCESS);
        if(postauth_conf(user))
            return -1;
        return 1;
    } else {
        ssh_say(1,"password auth failed for user %s\n",user);
        pam_end(pamh,PAM_AUTH_ERR);
        return 0;
    }
}



int do_auth(SSH_SESSION *session){
    SSH_MESSAGE *message;
    int auth=-1;
    do {
        message=ssh_message_get(session);
        if(!message)
            break;
        switch(ssh_message_type(message)){
            case SSH_AUTH_REQUEST:
                switch(ssh_message_subtype(message)){
                    case SSH_AUTH_PASSWORD:
                        ssh_say(1,"User %s wants to auth by password\n",
                                ssh_message_auth_user(message));
                        auth=auth_password(ssh_message_auth_user(message),
                                           ssh_message_auth_password(message));
                        switch(auth){
                            case 1:
                                ssh_say(1,"Authentication success\n");
                                ssh_message_auth_reply_success(message,0);
                                break;
                            case -1:
                                ssh_say(1,"Too much tries\n");
                                // too much auth tried
                                ssh_disconnect(session);
                                exit(1);
                            case 0:
                                ssh_say(1,"Auth refused\n");
                                break;
                        }
                        if(auth==1){
                            break;
                        } else {
                            ssh_message_auth_set_methods(message,SSH_AUTH_PASSWORD);
                            ssh_message_reply_default(message);
                        } 
                        break;
                        // not authenticated, send default message
                    case SSH_AUTH_NONE:
                        if(user_nopassword(ssh_message_auth_user(message))){
                            if(postauth_conf(ssh_message_auth_user(message))==0){
                                ssh_message_auth_reply_success(message,0);
                                auth=1;
                                ssh_say(1,"Authentication success for %s(no password)\n",
                                        ssh_message_auth_user(message));
                                break;
                            } else {
                                ssh_say(1,"Post-auth failed\n");
                                ssh_message_auth_set_methods(message,SSH_AUTH_PASSWORD);
                                ssh_message_reply_default(message);
                            }
                        } else {
                            ssh_message_auth_set_methods(message,SSH_AUTH_PASSWORD);
                            ssh_message_reply_default(message);
                        }
                        break;
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
    } while (auth!=1);
    return auth;
}
