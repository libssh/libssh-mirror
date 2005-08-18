/* channels1.c */
/* Support for SSH-1 type channels */
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

#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/ssh1.h"

#ifdef HAVE_SSH1

/* this is a big hack. In fact, SSH-1 doesn't make a clever use of channels.
 * The whole packets concerning Shells are sent outside of a channel.
 * Thus, an inside limitation of this behaviour is that you can't only
 * request one Shell.
 * And i don't even know yet how they managed to imbed two "channel"
 * into one protocol.
 */

int channel_open_session1(CHANNEL *chan){
    // we guess we are requesting an *exec* channel. It can only have
    // only one exec channel. so we abort with an error if we need more than
    SSH_SESSION *session=chan->session;
    if(session->exec_channel_opened){
        ssh_set_error(session,SSH_REQUEST_DENIED,"SSH-1 supports only one execution channel. One has already been opened");
        return -1;
    }
    session->exec_channel_opened=1;
    chan->open=1;
    ssh_say(2,"Opened a ssh1 channel session\n");
    return 0;
}
/*  10 SSH_CMSG_REQUEST_PTY
 *
 *  string       TERM environment variable value (e.g. vt100)
 *  32-bit int   terminal height, rows (e.g., 24)
 *  32-bit int   terminal width, columns (e.g., 80)
 *  32-bit int   terminal width, pixels (0 if no graphics) (e.g., 480)
 *  32-bit int   terminal height, pixels (0 if no graphics) (e.g., 640)
 *  n bytes      tty modes encoded in binary
 *  Some day, someone should have a look at that nasty tty encoded. It's
 *  much simplier under ssh2. I just hope the defaults values are ok ...
 */

int channel_request_pty_size1(CHANNEL *channel, char *terminal, int col, 
        int row){
    STRING *str;
    SSH_SESSION *session=channel->session;
    str=string_from_char(terminal);
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_REQUEST_PTY);
    buffer_add_ssh_string(session->out_buffer,str);
    free(str);
    buffer_add_u32(session->out_buffer,ntohl(row));
    buffer_add_u32(session->out_buffer,ntohl(col));
    buffer_add_u32(session->out_buffer,0); /* x */
    buffer_add_u32(session->out_buffer,0); /* y */
    buffer_add_u8(session->out_buffer,0); /* tty things */
    ssh_say(2,"Opening a ssh1 pty\n");
    if(packet_send(session))
        return -1;
    if(packet_read(session))
        return -1;
    if(packet_translate(session))
        return -1;
    switch (session->in_packet.type){
        case SSH_SMSG_SUCCESS:
            ssh_say(2,"pty : Success\n");
            return 0;
            break;
        case SSH_SMSG_FAILURE:
            ssh_set_error(session,SSH_REQUEST_DENIED,
                    "Server denied PTY allocation");
            ssh_say(2,"pty : denied\n");
            break;
        default:
            ssh_say(2,"pty : error\n");
            ssh_set_error(session,SSH_FATAL,
                    "Received unexpected packet type %d",
                    session->in_packet.type);
            return -1;
    }
    return -1;
}

int channel_change_pty_size1(CHANNEL *channel, int cols, int rows){
    SSH_SESSION *session=channel->session;
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_WINDOW_SIZE);
    buffer_add_u32(session->out_buffer,ntohl(rows));
    buffer_add_u32(session->out_buffer,ntohl(cols));
    buffer_add_u32(session->out_buffer,0);
    buffer_add_u32(session->out_buffer,0);
    if(packet_send(session))
        return -1;
    ssh_say(2,"Change pty size send\n");
    packet_wait(session,SSH_SMSG_SUCCESS,1);
    switch (session->in_packet.type){
        case SSH_SMSG_SUCCESS:
            ssh_say(2,"pty size changed\n");
            return 0;
            break;
        case SSH_SMSG_FAILURE:
            ssh_say(2,"pty size change denied\n");
            ssh_set_error(session,SSH_REQUEST_DENIED,"pty size change denied");
            return -1;
    }
    ssh_set_error(session,SSH_FATAL,"Received unexpected packet type %d",
            session->in_packet.type);
    return -1;
}

int channel_request_shell1(CHANNEL *channel){
    SSH_SESSION *session=channel->session;
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_EXEC_SHELL);
    if(packet_send(session))
        return -1;
    ssh_say(2,"Launched a shell\n");
    return 0;
}

int channel_request_exec1(CHANNEL *channel, char *cmd){
    SSH_SESSION *session=channel->session;
    STRING *command=string_from_char(cmd);
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_EXEC_CMD);
    buffer_add_ssh_string(session->out_buffer,command);
    free(command);
    if(packet_send(session))
        return -1;
    ssh_say(2,"executing %s...\n",cmd);
    return 0;
}

static void channel_rcv_data1(SSH_SESSION *session, int is_stderr){
    CHANNEL *channel;
    STRING *str;
    channel=session->channels; // Easy. hack this when multiple channel
                               // are comming
    str=buffer_get_ssh_string(session->in_buffer);
    if(!str){
        ssh_say(0,"Invalid data packet !\n");
        return;
    }
    ssh_say(3,"adding %d bytes data in %d\n",string_len(str),is_stderr);
    channel_default_bufferize(channel,str->string,string_len(str),
                    is_stderr);
    free(str);
}       

static void channel_rcv_close1(SSH_SESSION *session){
    CHANNEL *channel=session->channels;
    u32 status;
    buffer_get_u32(session->in_buffer,&status);
    /* it's much more than a channel closing. spec says it's the last 
     * message sent by server (strange)
     */
    /* actually status is lost somewhere */
    channel->open=0;
    channel->remote_eof=1;
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_EXIT_CONFIRMATION);
    packet_send(session);
}

void channel_handle1(SSH_SESSION *session, int type){
    ssh_say(3,"Channel_handle1(%d)\n",type);
    switch (type){
        case SSH_SMSG_STDOUT_DATA:
            channel_rcv_data1(session,0);
            break;
        case SSH_SMSG_EXITSTATUS:
            channel_rcv_close1(session);
            break;
        default:
            ssh_say(0,"Unexepected message %d\n",type);
            
    }
}

int channel_write1(CHANNEL *channel, void *data, int len){
    SSH_SESSION *session=channel->session;
    int origlen=len;
    int effectivelen;
    while(len>0){
        packet_clear_out(session);
        buffer_add_u8(session->out_buffer,SSH_CMSG_STDIN_DATA);
        if(len > 32000)
            effectivelen=32000;
        else
            effectivelen=len;
        buffer_add_u32(session->out_buffer,htonl(effectivelen));
        buffer_add_data(session->out_buffer,data,effectivelen);
        data+=effectivelen;
        len-=effectivelen;
        if(packet_send(session))
            return -1;
    }
    return origlen;
}

#endif /* HAVE_SSH1 */
