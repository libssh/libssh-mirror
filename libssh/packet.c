/*
 * packet.c - packet building functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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
 * MA 02111-1307, USA.
 *
 * vim: ts=2 sw=2 et cindent
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "config.h"
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/ssh1.h"
#include "libssh/crypto.h"

/* XXX include selected mac size */
static int macsize=SHA_DIGEST_LEN;

/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */


#define PACKET_STATE_INIT 0
#define PACKET_STATE_SIZEREAD 1

static int packet_read2(SSH_SESSION *session){
    u32 len;
    void *packet=NULL;
    unsigned char mac[30];
    char buffer[16];
    int to_be_read;
    int ret;
    u8 padding;
    unsigned int blocksize=(session->current_crypto?session->current_crypto->in_cipher->blocksize:8);
    int current_macsize=session->current_crypto?macsize:0;
    enter_function();
    if(!session->alive){
    	leave_function();
        return SSH_ERROR; // the error message was already set into this session
    }
    switch(session->packet_state){
        case PACKET_STATE_INIT:    
            memset(&session->in_packet,0,sizeof(PACKET));
            if(session->in_buffer)
                buffer_reinit(session->in_buffer);
            else
                session->in_buffer=buffer_new();
            ret=ssh_socket_wait_for_data(session->socket,session,blocksize);
            if(ret != SSH_OK){
                leave_function();
            	return ret; // can be SSH_ERROR or SSH_AGAIN
            }
//    be_read=completeread(session->fd,buffer,blocksize);
            // can't fail since we're sure there is enough data in socket buffer
            ssh_socket_read(session->socket,buffer,blocksize);
            len=packet_decrypt_len(session,buffer);
            buffer_add_data(session->in_buffer,buffer,blocksize);
            if(len> MAX_PACKET_LEN){
                ssh_set_error(session,SSH_FATAL,"read_packet(): Packet len too high(%uld %.8lx)",len,len);
                leave_function();
                return SSH_ERROR;
            }
            to_be_read=len-blocksize+sizeof(u32);
            if(to_be_read<0){
                /* remote sshd sends invalid sizes?*/
                ssh_set_error(session,SSH_FATAL,"given numbers of bytes left to be read <0 (%d)!",to_be_read);
                leave_function();
                return SSH_ERROR;
            }
            /* saves the status of the current operations */
            session->in_packet.len=len;
            session->packet_state=PACKET_STATE_SIZEREAD;
        case PACKET_STATE_SIZEREAD:
            len=session->in_packet.len;
            to_be_read=len-blocksize+sizeof(u32) + current_macsize;
            /* if to_be_read is zero, the whole packet was blocksize bytes. */
            if(to_be_read != 0){ 
                ret=ssh_socket_wait_for_data(session->socket,session,to_be_read);
                if(ret!=SSH_OK){
                    leave_function();
                    return ret;
                }
                packet = malloc(to_be_read);
                if (packet == NULL) {
                  ssh_set_error(session, SSH_FATAL, "No space left");
                  leave_function();
                  return SSH_ERROR;
                }
                ssh_socket_read(session->socket,packet,to_be_read-current_macsize);
                ssh_log(session,SSH_LOG_PACKET,"Read a %d bytes packet",len);
                buffer_add_data(session->in_buffer,packet,to_be_read-current_macsize);
                free(packet);
            }
            if(session->current_crypto){
                /* decrypt the rest of the packet (blocksize bytes already have been decrypted */
                if (packet_decrypt(session,
                      buffer_get(session->in_buffer) + blocksize,
                      buffer_get_len(session->in_buffer) - blocksize) < 0) {
                    ssh_set_error(session, SSH_FATAL, "Decrypt error");
                    leave_function();
                    return SSH_ERROR;
                }
                ssh_socket_read(session->socket,mac,macsize);
                if(packet_hmac_verify(session,session->in_buffer,mac)){
                    ssh_set_error(session,SSH_FATAL,"HMAC error");
                    leave_function();
                    return SSH_ERROR;
                }
            }
            buffer_pass_bytes(session->in_buffer,sizeof(u32));   
                /*pass the size which has been processed before*/
            if(!buffer_get_u8(session->in_buffer,&padding)){
                ssh_set_error(session,SSH_FATAL,"Packet too short to read padding");
                leave_function();
                return SSH_ERROR;
            }
            ssh_log(session, SSH_LOG_RARE,
                "%hhd bytes padding, %d bytes left in buffer",
                padding, buffer_get_rest_len(session->in_buffer));
            if(padding > buffer_get_rest_len(session->in_buffer)){
                ssh_set_error(session,SSH_FATAL,"invalid padding: %d (%d resting)",
                              padding,buffer_get_rest_len(session->in_buffer));
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("incrimined packet",
                               buffer_get(session->in_buffer),buffer_get_len(session->in_buffer));
#endif
                leave_function();
                return SSH_ERROR;
            }
            buffer_pass_bytes_end(session->in_buffer,padding);
            ssh_log(session, SSH_LOG_RARE,
                "After padding, %d bytes left in buffer",
                buffer_get_rest_len(session->in_buffer));
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
            if(session->current_crypto && session->current_crypto->do_compress_in){
                ssh_log(session, SSH_LOG_RARE, "Decompressing in_buffer ...");
                decompress_buffer(session,session->in_buffer);
            }
#endif
            session->recv_seq++;
            session->packet_state=PACKET_STATE_INIT;
            leave_function();
            return SSH_OK;
    }
    ssh_set_error(session,SSH_FATAL,"Invalid state into packet_read2() : %d",session->packet_state);
    leave_function();
    return SSH_ERROR;
}

#ifdef HAVE_SSH1
/* a slighty modified packet_read2() for SSH-1 protocol */
static int packet_read1(SSH_SESSION *session){
    u32 len;
    void *packet=NULL;
    int ret;
    int to_be_read;
    u32 padding;
    u32 crc;
    enter_function();
    if(!session->alive){
        leave_function();
    	return SSH_ERROR; // the error message was already set
    }
    switch (session->packet_state){
        case PACKET_STATE_INIT:
            memset(&session->in_packet,0,sizeof(PACKET));
            if(session->in_buffer)
                buffer_reinit(session->in_buffer);
            else
                session->in_buffer=buffer_new();
            ret=ssh_socket_read(session->socket,&len,sizeof(u32));
            if(ret!=SSH_OK){
                leave_function();
            	return ret; // could be SSH_AGAIN
            }
           /* len is not encrypted */
            len=ntohl(len); 
            if(len> MAX_PACKET_LEN){
                ssh_set_error(session,SSH_FATAL,"read_packet(): Packet len too high(%uld %.8lx)",len,len);
                leave_function();
                return SSH_ERROR;
            }
            ssh_log(session,SSH_LOG_PACKET,"reading a %d bytes packet",len);
            session->in_packet.len=len;
            session->packet_state=PACKET_STATE_SIZEREAD;
        case PACKET_STATE_SIZEREAD:
            len=session->in_packet.len;
            /* SSH-1 has a fixed padding lenght */
            padding=8-(len % 8);
            to_be_read=len+padding;
            /* it is *not* possible that to_be_read be < 8. */
            packet = malloc(to_be_read);
            if (packet == NULL) {
              ssh_set_error(session, SSH_FATAL,"No space left");
              leave_function();
              return SSH_ERROR;
            }
            ret=ssh_socket_read(session->socket,packet,to_be_read);
            if(ret != SSH_OK){
            	free(packet);
            	leave_function();
            	return ret; // can be SSH_ERROR or SSH_AGAIN
            }
            buffer_add_data(session->in_buffer,packet,to_be_read);
            free(packet);
            
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("read packet:",buffer_get(session->in_buffer),
                buffer_get_len(session->in_buffer));
#endif
            if (session->current_crypto) {
              /* we decrypt everything, missing the lenght part (which was
               * previously read, unencrypted, and is not part of the buffer
               */
              if (packet_decrypt(session,
                    buffer_get(session->in_buffer),
                    buffer_get_len(session->in_buffer)) < 0) {
                ssh_set_error(session, SSH_FATAL, "Packet decrypt error");
                leave_function();
                return SSH_ERROR;
              }
            }
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("read packet decrypted:",
                           buffer_get(session->in_buffer),buffer_get_len(session->in_buffer));
#endif
            ssh_log(session,SSH_LOG_PACKET,"%d bytes padding",padding);
            if((len+padding) != buffer_get_rest_len(session->in_buffer) || (len+padding) < sizeof(u32)){
                ssh_log(session,SSH_LOG_RARE,"no crc32 in packet");
                ssh_set_error(session,SSH_FATAL,"no crc32 in packet");
                leave_function();
                return SSH_ERROR;
            }
            memcpy(&crc,buffer_get_rest(session->in_buffer)+(len+padding)-sizeof(u32),
            sizeof(u32));
            buffer_pass_bytes_end(session->in_buffer,sizeof(u32));
            crc=ntohl(crc);
            if(ssh_crc32(buffer_get_rest(session->in_buffer),(len+padding)-sizeof(u32))!=crc){
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("crc32 on",buffer_get_rest(session->in_buffer),
                len + padding - sizeof(u32));
#endif
                ssh_log(session,SSH_LOG_RARE,"invalid crc32");
                ssh_set_error(session,SSH_FATAL,"invalid crc32 : expected %.8lx, "
                "got %.8lx",crc,
                ssh_crc32(buffer_get_rest(session->in_buffer),len+padding-sizeof(u32)) );
                leave_function();
                return SSH_ERROR;
            }
            buffer_pass_bytes(session->in_buffer,padding);   /*pass the padding*/
            ssh_log(session,SSH_LOG_PACKET,"the packet is valid");
/* will do that later 
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
    if(session->current_crypto && session->current_crypto->do_compress_in){
        decompress_buffer(session,session->in_buffer);
    }
#endif
*/
            session->recv_seq++;
            session->packet_state=PACKET_STATE_INIT;
            leave_function();
            return SSH_OK;
    }
    ssh_set_error(session,SSH_FATAL,"Invalid state into packet_read1() : %d",session->packet_state);
    leave_function();
    return SSH_ERROR;
}

#endif /* HAVE_SSH1 */

/* that's where i'd like C to be object ... */
int packet_read(SSH_SESSION *session){
#ifdef HAVE_SSH1
    if(session->version==1)
        return packet_read1(session);
    else
#endif
        return packet_read2(session);
}

int packet_translate(SSH_SESSION *session){
	enter_function();
    memset(&session->in_packet,0,sizeof(PACKET));
    if(!session->in_buffer){
        leave_function();
    	return -1;
    }
    ssh_log(session, SSH_LOG_RARE, "Final size %d",
        buffer_get_rest_len(session->in_buffer));
    if(!buffer_get_u8(session->in_buffer,&session->in_packet.type)){
        ssh_set_error(session,SSH_FATAL,"Packet too short to read type");
        leave_function();
        return -1;
    }
    ssh_log(session, SSH_LOG_RARE, "Type %hhd", session->in_packet.type);
    session->in_packet.valid=1;
    leave_function();
    return 0;
}

/* Write the the bufferized output. If the session is blocking, or enforce_blocking 
 * is set, the call may block. Otherwise, it won't block.
 * return SSH°OK if everything has been sent, SSH_AGAIN if there are still things 
 * to send on buffer, SSH_ERROR if there is an error. */
int packet_flush(SSH_SESSION *session, int enforce_blocking){
    if(enforce_blocking || session->blocking)
        return ssh_socket_blocking_flush(session->socket);
    return ssh_socket_nonblocking_flush(session->socket);
}

/* this function places the outgoing packet buffer into an outgoing socket buffer */
static int packet_write(SSH_SESSION *session){
	int ret;
	enter_function();
	ssh_socket_write(session->socket,buffer_get(session->out_buffer),buffer_get_len(session->out_buffer));
	ret=packet_flush(session,0);
	leave_function();
    return ret;
}

static int packet_send2(SSH_SESSION *session){
    char padstring[32];
    u32 finallen;
    u8 padding;
    u32 currentlen=buffer_get_len(session->out_buffer);
    unsigned char *hmac;
    int ret=0;
    unsigned int blocksize=(session->current_crypto?session->current_crypto->out_cipher->blocksize:8);
    enter_function();
    ssh_log(session, SSH_LOG_RARE,
        "Writing on the wire a packet having %u bytes before", currentlen);
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
    if(session->current_crypto && session->current_crypto->do_compress_out){
        ssh_log(session, SSH_LOG_RARE, "Compressing in_buffer ...");
        compress_buffer(session,session->out_buffer);
        currentlen=buffer_get_len(session->out_buffer);
    }
#endif
    padding=(blocksize- ((currentlen+5) % blocksize));
    if(padding<4)
        padding+=blocksize;
    if(session->current_crypto)
        ssh_get_random(padstring,padding,0);
    else
        memset(padstring,0,padding);
    finallen=htonl(currentlen+padding+1);
    ssh_log(session, SSH_LOG_RARE,
        "%d bytes after comp + %d padding bytes = %d bytes packet",
        currentlen, padding, (ntohl(finallen)));
    buffer_add_data_begin(session->out_buffer,&padding,sizeof(u8));
    buffer_add_data_begin(session->out_buffer,&finallen,sizeof(u32));
    buffer_add_data(session->out_buffer,padstring,padding);
    hmac=packet_encrypt(session,buffer_get(session->out_buffer),buffer_get_len(session->out_buffer));
    if(hmac)
        buffer_add_data(session->out_buffer,hmac,20);
    ret=packet_write(session);
    session->send_seq++;
    buffer_reinit(session->out_buffer);
    leave_function();
    return ret; /* SSH_OK, AGAIN or ERROR */
}

#ifdef HAVE_SSH1
static int packet_send1(SSH_SESSION *session){
    char padstring[32];
    u32 finallen;
    u8 padding;
    u32 crc;
    u32 currentlen=buffer_get_len(session->out_buffer)+sizeof(u32);
    int ret=0;
    unsigned int blocksize=(session->current_crypto?session->current_crypto->out_cipher->blocksize:8);
    enter_function();
    ssh_log(session,SSH_LOG_PACKET,"Sending a %d bytes long packet",currentlen);
/*
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
    if(session->current_crypto && session->current_crypto->do_compress_out){
        compress_buffer(session,session->out_buffer);
        currentlen=buffer_get_len(session->out_buffer);
    }
#endif
*/
    padding=blocksize-(currentlen % blocksize);
    if(session->current_crypto)
        ssh_get_random(padstring,padding,0);
    else
        memset(padstring,0,padding);
    finallen=htonl(currentlen);
    ssh_log(session,SSH_LOG_PACKET,"%d bytes after comp + %d padding bytes = %d bytes packet",currentlen,padding,(ntohl(finallen)));
    buffer_add_data_begin(session->out_buffer,&padstring,padding);
    buffer_add_data_begin(session->out_buffer,&finallen,sizeof(u32));
    crc=ssh_crc32(buffer_get(session->out_buffer)+sizeof(u32),buffer_get_len(session->out_buffer)-sizeof(u32));
    buffer_add_u32(session->out_buffer,ntohl(crc));
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("clear packet",buffer_get(session->out_buffer),
            buffer_get_len(session->out_buffer));
#endif
    packet_encrypt(session,buffer_get(session->out_buffer)+sizeof(u32),buffer_get_len(session->out_buffer)-sizeof(u32));
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("encrypted packet",buffer_get(session->out_buffer),
            buffer_get_len(session->out_buffer));
#endif
    ssh_socket_write(session->socket,buffer_get(session->out_buffer),buffer_get_len(session->out_buffer));
    ret=packet_flush(session,0);
    session->send_seq++;
    buffer_reinit(session->out_buffer);
    leave_function();
    return ret;     /* SSH_OK, AGAIN or ERROR */
}

#endif /* HAVE_SSH1 */

int packet_send(SSH_SESSION *session){
#ifdef HAVE_SSH1
    if (session->version==1)
        return packet_send1(session);
    else 
#endif
        return packet_send2(session);
}

void packet_parse(SSH_SESSION *session){
    int type=session->in_packet.type;
    u32 foo;
    STRING *error_s;
    char *error=NULL;
#ifdef HAVE_SSH1
    if(session->version==1){
        /* SSH-1 */
        switch(type){
            case SSH_MSG_DISCONNECT:
                ssh_log(session, SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT");
                ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_DISCONNECT");
                ssh_socket_close(session->socket);
                session->alive=0;
                return;
            case SSH_SMSG_STDOUT_DATA:
            case SSH_SMSG_STDERR_DATA:
            case SSH_SMSG_EXITSTATUS:
                channel_handle1(session,type);
                return;
            case SSH_MSG_DEBUG:
            case SSH_MSG_IGNORE:
            	break;
            default:
                ssh_log(session, SSH_LOG_PACKET,
                    "Unexpected message code %d", type);
            }
        return;
    } else {
#endif /* HAVE_SSH1 */
    switch(type){
        case SSH2_MSG_DISCONNECT:
            buffer_get_u32(session->in_buffer,&foo);
            error_s=buffer_get_ssh_string(session->in_buffer);
            if(error_s)
                error=string_to_char(error_s);
            ssh_log(session, SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT\n");
            ssh_set_error(session, SSH_FATAL,
                "Received SSH_MSG_DISCONNECT: %s",error);
            if(error_s){
                free(error_s);
                free(error);
            }
            ssh_socket_close(session->socket);
            session->alive=0;
            return;
        case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
        case SSH2_MSG_CHANNEL_DATA:
        case SSH2_MSG_CHANNEL_EXTENDED_DATA:
        case SSH2_MSG_CHANNEL_REQUEST:
        case SSH2_MSG_CHANNEL_EOF:
        case SSH2_MSG_CHANNEL_CLOSE:

            channel_handle(session,type);
        case SSH2_MSG_IGNORE:
        case SSH2_MSG_DEBUG:
            return;
        default:
            ssh_log(session,SSH_LOG_RARE,"Received unhandled packet %d",type);
    }
#ifdef HAVE_SSH1
    }
#endif
}    

#ifdef HAVE_SSH1
static int packet_wait1(SSH_SESSION *session,int type,int blocking){
	enter_function();
    ssh_log(session,SSH_LOG_PROTOCOL,"packet_wait1 waiting for %d",type);
    while(1){
        if(packet_read1(session) || packet_translate(session)){
            leave_function();
            return -1;
        }
        ssh_log(session,SSH_LOG_PACKET,"packet_wait 1 received a type %d packet",session->in_packet.type);
        switch(session->in_packet.type){
            case SSH_MSG_DISCONNECT:
                packet_parse(session);
                leave_function();
                return -1;
            case SSH_SMSG_STDOUT_DATA:
            case SSH_SMSG_STDERR_DATA:
            case SSH_SMSG_EXITSTATUS:
                channel_handle1(session,type);
                break;
            case SSH_MSG_DEBUG:
            case SSH_MSG_IGNORE:
            	break;
/*          case SSH2_MSG_CHANNEL_CLOSE:
               packet_parse(session);
                break;;
*/               
            default:
               if(type && (type != session->in_packet.type)){
                   ssh_set_error(session,SSH_FATAL,"waitpacket(): Received a %d type packet, was waiting for a %d\n",session->in_packet.type,type);
                   leave_function();
                   return -1;
               }
               leave_function();
               return 0;
           }
        if(blocking==0){
            leave_function();
        	return 0;
        }
    }
    leave_function();
    return 0;
}
#endif /* HAVE_SSH1 */
static int packet_wait2(SSH_SESSION *session,int type,int blocking){
    int ret;
    enter_function();
    while(1){
        ret=packet_read2(session);
        if(ret != SSH_OK){
            leave_function();
        	return ret;
        }
        if(packet_translate(session)){
            leave_function();
            return SSH_ERROR;
        }
        switch(session->in_packet.type){
           case SSH2_MSG_DISCONNECT:
               packet_parse(session);
               ssh_log(session, SSH_LOG_PACKET, "received disconnect packet");
               leave_function();
               return SSH_ERROR;
           case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
           case SSH2_MSG_CHANNEL_DATA:
           case SSH2_MSG_CHANNEL_EXTENDED_DATA:
           case SSH2_MSG_CHANNEL_REQUEST:
           case SSH2_MSG_CHANNEL_EOF:
           case SSH2_MSG_CHANNEL_CLOSE:
               packet_parse(session);
               break;
           case SSH2_MSG_IGNORE:
               break;
           default:
               if(type && (type != session->in_packet.type)){
                   ssh_set_error(session,SSH_FATAL,"waitpacket(): Received a %d type packet, was waiting for a %d\n",session->in_packet.type,type);
                   leave_function();
                   return SSH_ERROR;
               }
               leave_function();
               return SSH_OK;
           }
        if(blocking==0){
            leave_function();
        	return SSH_OK; //shouldn't it return SSH_AGAIN here ?
        }
    }
    leave_function();
    return SSH_OK;
}
int packet_wait(SSH_SESSION *session, int type, int block){
#ifdef HAVE_SSH1
    if(session->version==1)
        return packet_wait1(session,type,block);
    else
#endif
        return packet_wait2(session,type,block);
}
