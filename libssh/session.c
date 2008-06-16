/* session.c */
/* contains the non-networking functions ssh_* */
/*
 * Copyright (c) 2005-2008 Aris Adamantiadis
 *
 * This file is part of the SSH Library
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA. */

#include <string.h>
#include <stdlib.h>
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/server.h"
#define FIRST_CHANNEL 42 // why not ? it helps to find bugs.

/** \defgroup ssh_session SSH Session
 * \brief functions that manage a session
 */
/** \addtogroup ssh_session
 * @{ */

/** \brief creates a new ssh session
 * \returns new ssh_session pointer
 */
SSH_SESSION *ssh_new() {
    SSH_SESSION *session=malloc(sizeof (SSH_SESSION));
    memset(session,0,sizeof(SSH_SESSION));
    session->next_crypto=crypto_new();
    session->maxchannel=FIRST_CHANNEL;
    session->socket=ssh_socket_new(session);
    session->alive=0;
    session->blocking=1;
    session->log_indent=0;
    session->out_buffer=buffer_new();
    session->in_buffer=buffer_new();
    return session;
}

void ssh_cleanup(SSH_SESSION *session){
	enter_function();
    int i;
    if(session->serverbanner)
        free(session->serverbanner);
    if(session->clientbanner)
        free(session->clientbanner);
    if(session->in_buffer)
        buffer_free(session->in_buffer);
    if(session->out_buffer)
        buffer_free(session->out_buffer);
    if(session->banner)
        free(session->banner);
    if(session->options)
        ssh_options_free(session->options);
    if(session->current_crypto)
        crypto_free(session->current_crypto);
    if(session->next_crypto)
        crypto_free(session->next_crypto);
    if(session->socket)
    	ssh_socket_free(session->socket);
    // delete all channels
    while(session->channels)
        channel_free(session->channels);
    if(session->client_kex.methods)
        for(i=0;i<10;i++)
            if(session->client_kex.methods[i])
                free(session->client_kex.methods[i]);
    if(session->server_kex.methods)
        for(i=0;i<10;++i)
            if(session->server_kex.methods[i])
                free(session->server_kex.methods[i]);
    free(session->client_kex.methods);
    free(session->server_kex.methods);
    if(session->dsa_key)
        private_key_free(session->dsa_key);
    if(session->rsa_key)
        private_key_free(session->rsa_key);
    if(session->ssh_message){
        ssh_message_free(session->ssh_message);
        free(session->ssh_message);
    }
    memset(session,'X',sizeof(SSH_SESSION)); /* burn connection, it could hangs 
                                                sensitive datas */
    free(session);
    //leave_function();
}

/** \brief disconnect impolitely from remote host
 * \param session current ssh session
 */
void ssh_silent_disconnect(SSH_SESSION *session){
	enter_function();
    ssh_socket_close(session->socket);
    session->alive=0;
    ssh_disconnect(session);
    //leave_function();
}

/** \brief set the options for the current session
 * \param session ssh session
 * \param options options structure
 * \see ssh_new()
 * \see ssh_options_new()
 */
void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options){
    session->options=options;
    session->log_verbosity=options->log_verbosity;
}

/** \brief set the session in blocking/nonblocking mode
 * \param session ssh session
 * \param blocking zero for nonblocking mode
 * \bug nonblocking code is in development and won't work as expected
 */
void ssh_set_blocking(SSH_SESSION *session,int blocking){
    session->blocking=blocking?1:0;
}

/** In case you'd need the file descriptor of the connection 
 * to the server/client 
 * \brief recover the fd of connection
 * \param session ssh session
 * \return file descriptor of the connection, or -1 if it is
 * not connected
 */

socket_t ssh_get_fd(SSH_SESSION *session){
    return ssh_socket_get_fd(session->socket);
}

/** \brief say to the session it has data to read on the file descriptor without blocking
 * \param session ssh session
 */
void ssh_set_fd_toread(SSH_SESSION *session){
    session->data_to_read=1;
}

/** \brief say the session it may write to the file descriptor without blocking
 * \param session ssh session
 */
void ssh_set_fd_towrite(SSH_SESSION *session){
    session->data_to_write=1;
}

/** \brief say the session it has an exception to catch on the file descriptor
 * \param session ssh session
 */
void ssh_set_fd_except(SSH_SESSION *session){
    session->data_except=1;
}

/** \warning I don't remember if this should be internal or not
 */
/* looks if there is data to read on the socket and parse it. */
int ssh_handle_packets(SSH_SESSION *session){
    int w,err,r,i=0;
    enter_function();
    do {
        r=ssh_fd_poll(session,&w,&err);
        if(r<=0){
        	leave_function();
            return r; // error or no data available
        }
        /* if an exception happened, it will be trapped by packet_read() */
        if(packet_read(session)||packet_translate(session)){
            leave_function();
        	return -1;
        }
        packet_parse(session);
        ++i;
    } while(r>0 && i<5);
    leave_function();
    return r;
}

/** \brief get session status
 * \param session ssh session
 * \returns a bitmask including SSH_CLOSED, SSH_READ_PENDING or SSH_CLOSED_ERROR
 * which respectively means the session is closed, has data to read on the connection socket and session was closed due to an error
 */
int ssh_get_status(SSH_SESSION *session){
    int ret=0;
    if(session->closed)
        ret |= SSH_CLOSED;
    if(session->channel_bytes_toread > 0 || session->data_to_read)
        ret |= SSH_READ_PENDING;
    if(session->closed && session->closed_by_except)
        ret |= SSH_CLOSED_ERROR;
    return ret;
}

/** \brief get the disconnect message from the server
 * \param session ssh session
 * \return message sent by the server along with the disconnect, or NULL in which case the reason of the disconnect may be found with ssh_get_error.
 * \see ssh_get_error()
 */
const char *ssh_get_disconnect_message(SSH_SESSION *session){
    if(!session->closed)
        ssh_set_error(session,SSH_REQUEST_DENIED,"Connection not closed"
                " yet");
    else if(session->closed_by_except)
        ssh_set_error(session,SSH_REQUEST_DENIED,"Connection closed by "
                "socket error");
    else if(!session->discon_msg)
        ssh_set_error(session,SSH_FATAL,"Connection correctly closed but "
                "no disconnect message");
    else
        return session->discon_msg;
    return NULL;
}

/** \brief get the protocol version of the session
 * \param session ssh session
 * \return 1 or 2, for ssh1 or ssh2
 */
int ssh_get_version(SSH_SESSION *session){
    return session->version;
}

/** @} */

