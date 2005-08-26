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
#include <libssh/sftp.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define TYPE_DIR 1
#define TYPE_FILE 1
struct sftp_handle {
    int type;
    int offset;
    char *name;
    int eof;
    DIR *dir;
    FILE *file;
};

int auth_password(char *user, char *password){
    if(strcmp(user,"aris"))
        return 0;
    if(strcmp(password,"lala"))
        return 0;
    return 1; // authenticated 
}

int reply_status(SFTP_CLIENT_MESSAGE *msg){
    switch(errno){
        case EACCES:
            return sftp_reply_status(msg,SSH_FX_PERMISSION_DENIED,
                                     "permission denied");
        case ENOENT:
            return sftp_reply_status(msg,SSH_FX_NO_SUCH_FILE,
                                     "no such file or directory");
        case ENOTDIR:
            return sftp_reply_status(msg,SSH_FX_FAILURE,
                                     "not a directory");
        default:
            return sftp_reply_status(msg,SSH_FX_FAILURE,NULL);
    }
}

void handle_opendir(SFTP_CLIENT_MESSAGE *msg){
    DIR *dir=opendir(msg->filename);
    struct sftp_handle *hdl;
    STRING *handle;
    if(!dir){
        reply_status(msg);
        return;
    }
    hdl=malloc(sizeof(struct sftp_handle));
    memset(hdl,0,sizeof(struct sftp_handle));
    hdl->type=TYPE_DIR;
    hdl->offset=0;
    hdl->dir=dir;
    hdl->name=strdup(msg->filename);
    handle=sftp_handle_alloc(msg->sftp,hdl);
    sftp_reply_handle(msg,handle);
    free(handle);
}

SFTP_ATTRIBUTES *attr_from_stat(struct stat *statbuf){
    SFTP_ATTRIBUTES *attr=malloc(sizeof(SFTP_ATTRIBUTES));
    memset(attr,0,sizeof(*attr));
    attr->size=statbuf->st_size;
    attr->uid=statbuf->st_uid;
    attr->gid=statbuf->st_gid;
    attr->permissions=statbuf->st_mode;
    attr->atime=statbuf->st_atime;
    attr->mtime=statbuf->st_mtime;
    attr->flags=SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
    return attr;
}

int handle_lstat(SFTP_CLIENT_MESSAGE *msg){
    struct stat statbuf;
    SFTP_ATTRIBUTES *attr;
    if(lstat(msg->filename,&statbuf)){
        reply_status(msg);
        return 0;
    }
    attr=attr_from_stat(&statbuf);
    sftp_reply_attr(msg, attr);
    sftp_attributes_free(attr);
    return 0;
}

int handle_readdir(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    SFTP_ATTRIBUTES *attr;
    struct dirent *dir;
    struct stat statbuf;
    char file[1024];
    int i;
    if(!handle || handle->type!=TYPE_DIR){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    for(i=0; !handle->eof && i<10;++i){
        dir=readdir(handle->dir);
        if(!dir){
            handle->eof=1;
            break;
        }
        snprintf(file,sizeof(file),"%s/%s",handle->name,
                 dir->d_name);
        if(lstat(file,&statbuf)){
            memset(&statbuf,0,sizeof(statbuf));
        }
        attr=attr_from_stat(&statbuf);
        sftp_reply_names_add(msg,dir->d_name,file,attr);
        sftp_attributes_free(attr);
    }
    /* if there was at least one file, don't send the eof yet */
    if(i==0 && handle->eof){
        sftp_reply_status(msg,SSH_FX_EOF,NULL);
        return 0;
    }
    sftp_reply_names(msg);
    return 0;
}

int handle_close(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    if(!handle){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    sftp_handle_remove(msg->sftp,handle);
    if(handle->type==TYPE_DIR){
        closedir(handle->dir);
    } else {
        fclose(handle->file);
    }
    if(handle->name)
        free(handle->name);
    free(handle);
    sftp_reply_status(msg,SSH_FX_OK,NULL);
    return 0;
}

int sftploop(SSH_SESSION *session, SFTP_SESSION *sftp){
    SFTP_CLIENT_MESSAGE *msg;
    char buffer[PATH_MAX];
    do {
        msg=sftp_get_client_message(sftp);
        if(!msg)
            break;
        switch(msg->type){
            case SFTP_REALPATH:
                ssh_say(1,"client realpath : %s\n",msg->filename);
                realpath(msg->filename,buffer);
                ssh_say(2,"responding %s\n",buffer);
                sftp_reply_name(msg, buffer, NULL);
                break;
            case SFTP_OPENDIR:
                ssh_say(1,"client opendir(%s)\n",msg->filename);
                handle_opendir(msg);
                break;
            case SFTP_LSTAT:
                ssh_say(1,"client stat(%s)\n",msg->filename);
                handle_lstat(msg);
                break;
            case SFTP_READDIR:
                ssh_say(1,"client readdir\n");
                handle_readdir(msg);
                break;
            case SFTP_CLOSE:
                ssh_say(1,"client close\n");
                handle_close(msg);
                break;
        }
        sftp_client_message_free(msg);
    } while (1);
    if(!msg)
        return 1;
    return 0;
}

int do_auth(SSH_SESSION *session){
    SSH_MESSAGE *message;
    int auth=0;
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
                        ssh_message_auth_reply_success(message,0);
                        auth=1;
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
    } while (!auth);
    return auth;
}

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
    printf("Socket connected : %d\n",ssh_get_fd(session));
    if(ssh_accept(session)){
        printf("ssh_accept : %s\n",ssh_get_error(session));
        return 1;
    }
    if(do_auth(session)<=0){
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

