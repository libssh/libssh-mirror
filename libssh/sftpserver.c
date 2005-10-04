/* sftpserver.c contains server based function for the sftp protocol */
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
#include "libssh/libssh.h"
#include "libssh/sftp.h"
#include "libssh/ssh2.h"
#include "libssh/priv.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>

SFTP_CLIENT_MESSAGE *sftp_get_client_message(SFTP_SESSION *sftp){
    SFTP_PACKET *packet=sftp_packet_read(sftp);
    SFTP_CLIENT_MESSAGE *msg=malloc(sizeof (SFTP_CLIENT_MESSAGE));
    BUFFER *payload;
    STRING *tmp;
    memset(msg,0,sizeof(SFTP_CLIENT_MESSAGE));
    if(!packet)
        return NULL;
    payload=packet->payload;
    ssh_say(2,"received sftp packet type %d\n",packet->type);
    msg->type=packet->type;
    msg->sftp=sftp;
    buffer_get_u32(payload,&msg->id);
    switch(msg->type){
        case SSH_FXP_CLOSE:
        case SSH_FXP_READDIR:
            msg->handle=buffer_get_ssh_string(payload);
            break;
        case SSH_FXP_READ:
            msg->handle=buffer_get_ssh_string(payload);
            buffer_get_u64(payload,&msg->offset);
            buffer_get_u32(payload,&msg->len);
            break;
        case SSH_FXP_WRITE:
            msg->handle=buffer_get_ssh_string(payload);
            buffer_get_u64(payload,&msg->offset);
            msg->data=buffer_get_ssh_string(payload);
            break;
        case SSH_FXP_REMOVE:
        case SSH_FXP_RMDIR:
        case SSH_FXP_OPENDIR:
        case SSH_FXP_READLINK:
        case SSH_FXP_REALPATH:
            tmp=buffer_get_ssh_string(payload);
            msg->filename=string_to_char(tmp);
            free(tmp);
            break;
        case SSH_FXP_RENAME:
        case SSH_FXP_SYMLINK:
            tmp=buffer_get_ssh_string(payload);
            msg->filename=string_to_char(tmp);
            free(tmp);
            msg->data=buffer_get_ssh_string(payload);
            break;
        case SSH_FXP_MKDIR:
        case SSH_FXP_SETSTAT:
            tmp=buffer_get_ssh_string(payload);
            msg->filename=string_to_char(tmp);
            free(tmp);
            msg->attr=sftp_parse_attr(sftp, payload,0);
            break;
        case SSH_FXP_FSETSTAT:
            msg->handle=buffer_get_ssh_string(payload);
            msg->attr=sftp_parse_attr(sftp, payload,0);
            break;
        case SSH_FXP_LSTAT:
        case SSH_FXP_STAT:
            tmp=buffer_get_ssh_string(payload);
            msg->filename=string_to_char(tmp);
            free(tmp);
            if(sftp->version >3)
                buffer_get_u32(payload,&msg->flags);
            break;
        case SSH_FXP_OPEN:
            tmp=buffer_get_ssh_string(payload);
            msg->filename=string_to_char(tmp);
            free(tmp);
            buffer_get_u32(payload,&msg->flags);
            msg->attr=sftp_parse_attr(sftp, payload,0);
        case SSH_FXP_FSTAT:
            msg->handle=buffer_get_ssh_string(payload);
            buffer_get_u32(payload,&msg->flags);
            break;
        default:
            printf("Received handled sftp message %d\n",msg->type);
    }
    msg->flags=ntohl(msg->flags);
    msg->offset=ntohll(msg->offset);
    msg->len=ntohl(msg->len);
    sftp_packet_free(packet);
    return msg;
}

void sftp_client_message_free(SFTP_CLIENT_MESSAGE *msg){
    if(msg->filename)
        free(msg->filename);
    if(msg->data)
        free(msg->data);
    if(msg->attr)
        sftp_attributes_free(msg->attr);
    if(msg->handle)
        free(msg->handle);
    memset(msg,'X',sizeof(*msg));
    free(msg);
}

int sftp_reply_name(SFTP_CLIENT_MESSAGE *msg, char *name, SFTP_ATTRIBUTES *attr){
    BUFFER *out=buffer_new();
    STRING *file=string_from_char(name);
    int r;
    buffer_add_u32(out,msg->id);
    buffer_add_u32(out,htonl(1));
    buffer_add_ssh_string(out,file);
    buffer_add_ssh_string(out,file); /* the protocol is broken here between 3 & 4 */
    free(file);
    buffer_add_attributes(out,attr);
    r=sftp_packet_write(msg->sftp,SSH_FXP_NAME,out);
    buffer_free(out);
    return r<0;
}

int sftp_reply_handle(SFTP_CLIENT_MESSAGE *msg, STRING *handle){
    BUFFER *out=buffer_new();
    int r;
    buffer_add_u32(out,msg->id);
    buffer_add_ssh_string(out,handle);
    r=sftp_packet_write(msg->sftp,SSH_FXP_HANDLE,out);
    buffer_free(out);
    return r<0;
}

int sftp_reply_attr(SFTP_CLIENT_MESSAGE *msg, SFTP_ATTRIBUTES *attr){
    BUFFER *out=buffer_new();
    int r;
    buffer_add_u32(out,msg->id);
    buffer_add_attributes(out,attr);
    r=sftp_packet_write(msg->sftp,SSH_FXP_ATTRS,out);
    buffer_free(out);
    return r<0;
}

int sftp_reply_names_add(SFTP_CLIENT_MESSAGE *msg, char *file, char *longname,
        SFTP_ATTRIBUTES *attr){
    STRING *name=string_from_char(file);
    if(!msg->attrbuf)
        msg->attrbuf=buffer_new();
    buffer_add_ssh_string(msg->attrbuf,name);
    free(name);
    name=string_from_char(longname);
    buffer_add_ssh_string(msg->attrbuf,name);
    free(name);
    buffer_add_attributes(msg->attrbuf,attr);
    msg->attr_num++;
    return 0;
}

int sftp_reply_names(SFTP_CLIENT_MESSAGE *msg){
    BUFFER *out=buffer_new();
    int r;
    buffer_add_u32(out,msg->id);
    buffer_add_u32(out,htonl(msg->attr_num));
    buffer_add_data(out,buffer_get(msg->attrbuf),
                    buffer_get_len(msg->attrbuf));
    r=sftp_packet_write(msg->sftp,SSH_FXP_NAME,out);
    buffer_free(out);
    buffer_free(msg->attrbuf);
    msg->attr_num=0;
    msg->attrbuf=NULL;
    return r<0;
}

    
int sftp_reply_status(SFTP_CLIENT_MESSAGE *msg, u32 status, char *message){
    BUFFER *out=buffer_new();
    int r;
    STRING *s;
    buffer_add_u32(out,msg->id);
    buffer_add_u32(out,htonl(status));
    s=string_from_char(message?message:"");
    buffer_add_ssh_string(out,s);
    free(s);
    buffer_add_u32(out,0); // language string 
    r=sftp_packet_write(msg->sftp,SSH_FXP_STATUS,out);
    buffer_free(out);
    return r<0;
}

int sftp_reply_data(SFTP_CLIENT_MESSAGE *msg, void *data, int len){
    BUFFER *out=buffer_new();
    int r;
    buffer_add_u32(out,msg->id);
    buffer_add_u32(out,ntohl(len));
    buffer_add_data(out,data,len);
    r=sftp_packet_write(msg->sftp,SSH_FXP_DATA,out);
    buffer_free(out);
    return r<0;
}

/* this function will return you a new handle to give the client.
 * the function accepts an info that can be retrieved later with
 * the handle. Care is given that a corrupted handle won't give a
 * valid info (or worse). */
STRING *sftp_handle_alloc(SFTP_SESSION *sftp, void *info){
    int i;
    u32 val;
    STRING *ret;
    if(!sftp->handles){
        sftp->handles=malloc(sizeof(void *) * SFTP_HANDLES);
        memset(sftp->handles,0,sizeof(void *)*SFTP_HANDLES);
    }
    for(i=0; i<SFTP_HANDLES;++i)
        if(!sftp->handles[i])
            break;
    if(i==SFTP_HANDLES)
        return NULL; // no handle available
    val=i;
    ret=string_new(4);
    memcpy(ret->string,&val,sizeof(u32));
    sftp->handles[i]=info;
    return ret;
}

void *sftp_handle(SFTP_SESSION *sftp, STRING *handle){
    u32 val;
    if(!sftp->handles)
        return NULL;
    if(string_len(handle)!=sizeof(val))
        return NULL;
    memcpy(&val,handle->string,sizeof(u32));
    if(val>SFTP_HANDLES)
        return NULL;
    return sftp->handles[val];
}

void sftp_handle_remove(SFTP_SESSION *sftp, void *handle){
    int i;
    for(i=0;i<SFTP_HANDLES;++i){
        if(sftp->handles[i]==handle){
            sftp->handles[i]=NULL;
            break;
        }
    }
}
