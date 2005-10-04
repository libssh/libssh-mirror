/* messages.c */
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

/* this file contains the Message parsing utilities for server programs using 
 * libssh. The main loop of the program will call ssh_message_get(session) to 
 * get messages as they come. they are not 1-1 with the protocol messages.
 * then, the user will know what kind of a message it is and use the appropriate
 * functions to handle it (or use the default handlers if she doesn't know what to
 * do */

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#include "libssh/ssh2.h"
#include <netdb.h>
#include <string.h>
#include <stdlib.h>

static SSH_MESSAGE *message_new(SSH_SESSION *session){
    SSH_MESSAGE *msg=session->ssh_message;
    if(!msg){
        msg=malloc(sizeof(SSH_MESSAGE));
        session->ssh_message=msg;
    }
    memset(msg,0,sizeof (*msg));
    msg->session=session;
    return msg;
}

static int handle_service_request(SSH_SESSION *session){
    STRING *service;
    char *service_c;
    service=buffer_get_ssh_string(session->in_buffer);
    if(!service){
        ssh_set_error(session,SSH_FATAL,"Invalid SSH_MSG_SERVICE_REQUEST packet");
        return -1;
    }
    service_c=string_to_char(service);
    ssh_say(2,"Sending a SERVICE_ACCEPT for service %s\n",service_c);
    free(service_c);
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH2_MSG_SERVICE_ACCEPT);
    buffer_add_ssh_string(session->out_buffer,service);
    packet_send(session);
    free(service);
    return 0;
}

static void handle_unimplemented(SSH_SESSION *session){
    packet_clear_out(session);
    buffer_add_u32(session->out_buffer,htonl(session->recv_seq-1));
    packet_send(session);
}

static SSH_MESSAGE *handle_userauth_request(SSH_SESSION *session){
    STRING *user=buffer_get_ssh_string(session->in_buffer);
    STRING *service=buffer_get_ssh_string(session->in_buffer);
    STRING *method=buffer_get_ssh_string(session->in_buffer);
    SSH_MESSAGE *msg;
    char *service_c,*method_c;
    msg=message_new(session);
    msg->type=SSH_AUTH_REQUEST;
    msg->auth_request.username=string_to_char(user);
    free(user);
    service_c=string_to_char(service);
    method_c=string_to_char(method);
    ssh_say(2,"auth request for service %s, method %s for user '%s'\n",service_c,method_c,
            msg->auth_request.username);
    free(service_c);
    if(!strcmp(method_c,"none")){
        msg->auth_request.method=SSH_AUTH_NONE;
        free(method_c);
        return msg;
    }
    if(!strcmp(method_c,"password")){
        STRING *pass;
        u8 tmp;
        msg->auth_request.method=SSH_AUTH_PASSWORD;
        free(method_c);
        buffer_get_u8(session->in_buffer,&tmp);
        pass=buffer_get_ssh_string(session->in_buffer);
        msg->auth_request.password=string_to_char(pass);
        free(pass);
        return msg;
    }
    msg->auth_request.method=SSH_AUTH_UNKNOWN;
    free(method_c);
    return msg;
}

char *ssh_message_auth_user(SSH_MESSAGE *msg){
    return msg->auth_request.username;
}

char *ssh_message_auth_password(SSH_MESSAGE *msg){
    return msg->auth_request.password;
}

void ssh_message_auth_set_methods(SSH_MESSAGE *msg,int methods){
    msg->session->auth_methods=methods;
}

static int ssh_message_auth_reply_default(SSH_MESSAGE *msg,int partial){
    char methods_c[128]="";
    STRING *methods;
    packet_clear_out(msg->session);
    buffer_add_u8(msg->session->out_buffer,SSH2_MSG_USERAUTH_FAILURE);
    if(msg->session->auth_methods==0){
        msg->session->auth_methods=SSH_AUTH_PUBLICKEY|SSH_AUTH_PASSWORD;
    }
    if(msg->session->auth_methods & SSH_AUTH_PUBLICKEY)
        strcat(methods_c,"publickey,");
    if(msg->session->auth_methods & SSH_AUTH_KEYBINT)
        strcat(methods_c,"keyboard-interactive,");
    if(msg->session->auth_methods & SSH_AUTH_PASSWORD)
        strcat(methods_c,"password,");
    if(msg->session->auth_methods & SSH_AUTH_HOSTBASED)
        strcat(methods_c,"hostbased,");
    methods_c[strlen(methods_c)-1]=0; // strip the comma. We are sure there is at 
    // least one word into the list
    ssh_say(2,"Sending a auth failure. methods that can continue : %s\n",methods_c);
    methods=string_from_char(methods_c);
    buffer_add_ssh_string(msg->session->out_buffer,methods);
    free(methods);
    if(partial)
        buffer_add_u8(msg->session->out_buffer,1);
    else
        buffer_add_u8(msg->session->out_buffer,0); // no partial success
    return packet_send(msg->session);
}

int ssh_message_auth_reply_success(SSH_MESSAGE *msg,int partial){
    if(partial)
        return ssh_message_auth_reply_default(msg,partial);
    packet_clear_out(msg->session);
    buffer_add_u8(msg->session->out_buffer,SSH2_MSG_USERAUTH_SUCCESS);
    return packet_send(msg->session);
}

static SSH_MESSAGE *handle_channel_request_open(SSH_SESSION *session){
    SSH_MESSAGE *msg=message_new(session);
    STRING *type;
    char *type_c;
    u32 sender,window,packet;
    msg->type=SSH_CHANNEL_REQUEST_OPEN;
    type=buffer_get_ssh_string(session->in_buffer);
    type_c=string_to_char(type);
    ssh_say(2,"clients wants to open a %s channel\n",type_c);
    free(type);
    buffer_get_u32(session->in_buffer,&sender);
    buffer_get_u32(session->in_buffer,&window);
    buffer_get_u32(session->in_buffer,&packet);
    msg->channel_request_open.sender=ntohl(sender);
    msg->channel_request_open.window=ntohl(window);
    msg->channel_request_open.packet_size=ntohl(packet);
    if(!strcmp(type_c,"session")){
        msg->channel_request_open.type=SSH_CHANNEL_SESSION;
        return msg;
    }
    msg->channel_request_open.type=SSH_CHANNEL_UNKNOWN;
    return msg;
}

CHANNEL *ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg){
    CHANNEL *chan=channel_new(msg->session);
    chan->local_channel=ssh_channel_new_id(msg->session);
    chan->local_maxpacket=35000;
    chan->local_window=32000;
    chan->remote_channel=msg->channel_request_open.sender;
    chan->remote_maxpacket=msg->channel_request_open.packet_size;
    chan->remote_window=msg->channel_request_open.window;
    chan->open=1;
    packet_clear_out(msg->session);
    buffer_add_u8(msg->session->out_buffer,SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
    buffer_add_u32(msg->session->out_buffer,htonl(chan->remote_channel));
    buffer_add_u32(msg->session->out_buffer,htonl(chan->local_channel));
    buffer_add_u32(msg->session->out_buffer,htonl(chan->local_window));
    buffer_add_u32(msg->session->out_buffer,htonl(chan->local_maxpacket));
    ssh_say(2,"Accepting a channel request_open for chan %d\n",chan->remote_channel);
    if(packet_send(msg->session)){
        channel_free(chan);
        return NULL;
    }
    return chan;
}

static int ssh_message_channel_request_open_reply_default(SSH_MESSAGE *msg){
    ssh_say(2,"Refusing a channel\n");
    packet_clear_out(msg->session);
    buffer_add_u8(msg->session->out_buffer,SSH2_MSG_CHANNEL_OPEN_FAILURE);
    buffer_add_u32(msg->session->out_buffer,htonl(msg->channel_request_open.sender));
    buffer_add_u32(msg->session->out_buffer,htonl(SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED));
    buffer_add_u32(msg->session->out_buffer,0); // reason is an empty string
    buffer_add_u32(msg->session->out_buffer,0); // language too
    return packet_send(msg->session);
}

static SSH_MESSAGE *handle_channel_request(SSH_SESSION *session){
    u32 channel;
    STRING *type;
    char *type_c;
    u8 want_reply;
    SSH_MESSAGE *msg=message_new(session);
    buffer_get_u32(session->in_buffer,&channel);
    channel=ntohl(channel);
    type=buffer_get_ssh_string(session->in_buffer);
    buffer_get_u8(session->in_buffer,&want_reply);
    type_c=string_to_char(type);
    free(type);
    ssh_say(2,"received a %s channel_request for channel %d (want_reply=%hhd)\n",
            type_c,channel,want_reply);
    msg->type=SSH_CHANNEL_REQUEST;
    msg->channel_request.channel=ssh_channel_from_local(session,channel);
    msg->channel_request.want_reply=want_reply;
    if(!strcmp(type_c,"pty-req")){
        STRING *term;
        char *term_c;
        term=buffer_get_ssh_string(session->in_buffer);
        term_c=string_to_char(term);
        free(term);
        msg->channel_request.type=SSH_CHANNEL_REQUEST_PTY;
        msg->channel_request.TERM=term_c;
        buffer_get_u32(session->in_buffer,&msg->channel_request.width);
        buffer_get_u32(session->in_buffer,&msg->channel_request.height);
        buffer_get_u32(session->in_buffer,&msg->channel_request.pxwidth);
        buffer_get_u32(session->in_buffer,&msg->channel_request.pxheight);
        msg->channel_request.width=ntohl(msg->channel_request.width);
        msg->channel_request.height=ntohl(msg->channel_request.height);
        msg->channel_request.pxwidth=ntohl(msg->channel_request.pxwidth);
        msg->channel_request.pxheight=ntohl(msg->channel_request.pxheight);
        msg->channel_request.modes=buffer_get_ssh_string(session->in_buffer);
        return msg;
    }
    if(!strcmp(type_c,"subsystem")){
        STRING *subsys;
        char *subsys_c;
        subsys=buffer_get_ssh_string(session->in_buffer);
        subsys_c=string_to_char(subsys);
        free(subsys);
        msg->channel_request.type=SSH_CHANNEL_REQUEST_SUBSYSTEM;
        msg->channel_request.subsystem=subsys_c;
        return msg;
    }
    if(!strcmp(type_c,"shell")){
        msg->channel_request.type=SSH_CHANNEL_REQUEST_SHELL;
        return msg;
    }
    if(!strcmp(type_c,"exec")){
        STRING *cmd=buffer_get_ssh_string(session->in_buffer);
        msg->channel_request.type=SSH_CHANNEL_REQUEST_EXEC;
        msg->channel_request.command=string_to_char(cmd);
        free(cmd);
        return msg;
    }
    
    msg->channel_request.type=SSH_CHANNEL_UNKNOWN;
    return msg;
}

char *ssh_message_channel_request_subsystem(SSH_MESSAGE *msg){
    return msg->channel_request.subsystem;
}

int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg){
    u32 channel;
    if(msg->channel_request.want_reply){
        channel=msg->channel_request.channel->remote_channel;
        ssh_say(2,"Sending a channel_request success to channel %d\n",channel);
        packet_clear_out(msg->session);
        buffer_add_u8(msg->session->out_buffer,SSH2_MSG_CHANNEL_SUCCESS);
        buffer_add_u32(msg->session->out_buffer,htonl(channel));
        return packet_send(msg->session);
    } else {
        ssh_say(2,"The client doesn't want to know the request successed\n");
        return 0;
    }
}

static int ssh_message_channel_request_reply_default(SSH_MESSAGE *msg){
    u32 channel;
    if(msg->channel_request.want_reply){
        channel=msg->channel_request.channel->remote_channel;
        ssh_say(2,"Sending a default channel_request denied to channel %d\n",channel);
        packet_clear_out(msg->session);
        buffer_add_u8(msg->session->out_buffer,SSH2_MSG_CHANNEL_FAILURE);
        buffer_add_u32(msg->session->out_buffer,htonl(channel));
        return packet_send(msg->session);
    } else {
        ssh_say(2,"The client doesn't want to know the request failed ! \n");
        return 0;
    }
}

SSH_MESSAGE *ssh_message_get(SSH_SESSION *session){
    while(1){
        if(packet_read(session))
            return NULL;
        if(packet_translate(session))
            return NULL;
        switch(session->in_packet.type){
            case SSH2_MSG_SERVICE_REQUEST:
                if(handle_service_request(session))
                    return NULL;
                break;
            case SSH2_MSG_IGNORE:
            case SSH2_MSG_DEBUG:
                break;
            case SSH2_MSG_USERAUTH_REQUEST:
                return handle_userauth_request(session);
                break;
            case SSH2_MSG_CHANNEL_OPEN:
                return handle_channel_request_open(session);
                break;
            case SSH2_MSG_CHANNEL_REQUEST:
                return handle_channel_request(session);
                break;
            default:
                handle_unimplemented(session);
                ssh_set_error(session,SSH_FATAL,"Unhandled message %d\n",session->in_packet.type);
                return NULL;
        }
    }
    return NULL;
}

int ssh_message_type(SSH_MESSAGE *msg){
    return msg->type;
}

int ssh_message_subtype(SSH_MESSAGE *msg){
    switch(msg->type){
        case SSH_AUTH_REQUEST:
            return msg->auth_request.method;
        case SSH_CHANNEL_REQUEST_OPEN:
            return msg->channel_request_open.type;
        case SSH_CHANNEL_REQUEST:
            return msg->channel_request.type;
    }
    return -1;
}

int ssh_message_reply_default(SSH_MESSAGE *msg){
    switch(msg->type){
        case SSH_AUTH_REQUEST:
            return ssh_message_auth_reply_default(msg,0);
            break;
        case SSH_CHANNEL_REQUEST_OPEN:
            return ssh_message_channel_request_open_reply_default(msg);
            break;
        case SSH_CHANNEL_REQUEST:
            return ssh_message_channel_request_reply_default(msg);
            break;
        default:
            ssh_say(1,"Don't know what to default reply to %d type\n",
                    msg->type);
            break;
    }
    return 0;
}

void ssh_message_free(SSH_MESSAGE *msg){
    switch(msg->type){
        case SSH_AUTH_REQUEST:
            if(msg->auth_request.username)
                free(msg->auth_request.username);
            if(msg->auth_request.password){
                memset(msg->auth_request.password,0,strlen(msg->auth_request.password));
                free(msg->auth_request.password);
            }
            break;
        case SSH_CHANNEL_REQUEST_OPEN:
            if(msg->channel_request_open.originator)
                free(msg->channel_request_open.originator);
            if(msg->channel_request_open.destination)
                free(msg->channel_request_open.destination);
            break;
        case SSH_CHANNEL_REQUEST:
            if(msg->channel_request.TERM)
                free(msg->channel_request.TERM);
            if(msg->channel_request.modes)
                free(msg->channel_request.modes);
            if(msg->channel_request.var_name)
                free(msg->channel_request.var_name);
            if(msg->channel_request.var_value)
                free(msg->channel_request.var_value);
            if(msg->channel_request.command)
                free(msg->channel_request.command);
            if(msg->channel_request.subsystem)
                free(msg->channel_request.subsystem);
            break;
    }
    memset(msg,0,sizeof(*msg));
}
