/* packet.c */	
/* packet building functions */
/*
Copyright 2003 Aris Adamantiadis

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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/ssh1.h"
#include <netdb.h>
#include <errno.h>
#include "libssh/crypto.h"

/* XXX include selected mac size */
static int macsize=SHA_DIGEST_LEN;

/* completeread will read blocking until len bytes have been read */
static int completeread(int fd, void *buffer, int len){
    int r;
    int total=0;
    int toread=len;
    if(fd<0)
        return SSH_ERROR;
    while((r=read(fd,buffer+total,toread))){
        if(r==-1)
            return SSH_ERROR;
        total += r;
        toread-=r;
        if(total==len)
            return len;
        if(r==0)
            return 0;
    }
    return total ; /* connection closed */
}

/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */

static int socket_read(SSH_SESSION *session,int len){
    int except, can_write;
    int to_read;
    int r;
    char *buf;
    char buffer[4096];
    if(!session->in_socket_buffer)
        session->in_socket_buffer=buffer_new();
    to_read=len - buffer_get_rest_len(session->in_socket_buffer);
    if(to_read <= 0)
        return SSH_OK;
    if(session->blocking){
        buf=malloc(to_read);
        r=completeread(session->fd,buf,to_read);
        session->data_to_read=0;
        if(r==SSH_ERROR || r ==0){
            ssh_set_error(session,SSH_FATAL,
                (r==0)?"Connection closed by remote host" : "Error reading socket");
            close(session->fd);
            session->fd=-1;
            session->alive=0;
            session->data_except=1;
            return SSH_ERROR;
        }

        buffer_add_data(session->in_socket_buffer,buf,to_read);
        free(buf);
        return SSH_OK;
    }
    /* nonblocking read */
    do {
        ssh_fd_poll(session,&can_write,&except); /* internally sets data_to_read */
        if(!session->data_to_read)
            return SSH_AGAIN;
        session->data_to_read=0;
        /* read as much as we can */
        if(session->fd>0)
            r=read(session->fd,buffer,sizeof(buffer));
        else
            r=-1;
        if(r<=0){
            ssh_set_error(session,SSH_FATAL,
                (r==0)?"Connection closed by remote host" : "Error reading socket");
            if(session->fd>=0)
                close(session->fd);
            session->fd=-1;
            session->data_except=1;
            session->alive=0;
            return SSH_ERROR;
        }
        buffer_add_data(session->in_socket_buffer,buffer,r);
    } while(buffer_get_rest_len(session->in_socket_buffer)<len);
    return SSH_OK;
}

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
    if(!session->alive || session->data_except)
        return SSH_ERROR; // the error message was already set into this session
    switch(session->packet_state){
        case PACKET_STATE_INIT:    
            memset(&session->in_packet,0,sizeof(PACKET));
            if(session->in_buffer)
                buffer_reinit(session->in_buffer);
            else
                session->in_buffer=buffer_new();
            ret=socket_read(session,blocksize);
            if(ret != SSH_OK)
                return ret; // can be SSH_ERROR or SSH_AGAIN
//    be_read=completeread(session->fd,buffer,blocksize);
            memcpy(buffer,buffer_get_rest(session->in_socket_buffer),blocksize);
            buffer_pass_bytes(session->in_socket_buffer,blocksize); // mark them as read
            len=packet_decrypt_len(session,buffer);
            buffer_add_data(session->in_buffer,buffer,blocksize);
            if(len> MAX_PACKET_LEN){
                ssh_set_error(session,SSH_FATAL,"read_packet(): Packet len too high(%uld %.8lx)",len,len);
                return SSH_ERROR;
            }
            to_be_read=len-blocksize+sizeof(u32);
            if(to_be_read<0){
                /* remote sshd sends invalid sizes?*/
                ssh_set_error(session,SSH_FATAL,"given numbers of bytes left to be read <0 (%d)!",to_be_read);
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
                ret=socket_read(session,to_be_read);
                if(ret!=SSH_OK)
                    return ret;
                packet=malloc(to_be_read);
                memcpy(packet,buffer_get_rest(session->in_socket_buffer),to_be_read-current_macsize);
                buffer_pass_bytes(session->in_socket_buffer,to_be_read-current_macsize);
                ssh_say(3,"Read a %d bytes packet\n",len);
                buffer_add_data(session->in_buffer,packet,to_be_read-current_macsize);
                free(packet);
            }
            if(session->current_crypto){
                /* decrypt the rest of the packet (blocksize bytes already have been decrypted */
                packet_decrypt(session,buffer_get(session->in_buffer)+blocksize,
                               buffer_get_len(session->in_buffer)-blocksize);
                memcpy(mac,buffer_get_rest(session->in_socket_buffer),macsize);
                buffer_pass_bytes(session->in_socket_buffer,macsize);
                if(packet_hmac_verify(session,session->in_buffer,mac)){
                    ssh_set_error(session,SSH_FATAL,"HMAC error");
                    return SSH_ERROR;
                }
            }
            buffer_pass_bytes(session->in_buffer,sizeof(u32));   
                /*pass the size which has been processed before*/
            if(!buffer_get_u8(session->in_buffer,&padding)){
                ssh_set_error(session,SSH_FATAL,"Packet too short to read padding");
                return SSH_ERROR;
            }
            ssh_say(3,"%hhd bytes padding, %d bytes left in buffer\n",
                    padding,buffer_get_rest_len(session->in_buffer));
            if(padding > buffer_get_rest_len(session->in_buffer)){
                ssh_set_error(session,SSH_FATAL,"invalid padding: %d (%d resting)",
                              padding,buffer_get_rest_len(session->in_buffer));
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("incrimined packet",
                               buffer_get(session->in_buffer),buffer_get_len(session->in_buffer));
#endif
                return SSH_ERROR;
            }
            buffer_pass_bytes_end(session->in_buffer,padding);
            ssh_say(3,"After padding, %d bytes left in buffer\n",buffer_get_rest_len(session->in_buffer));
#ifdef HAVE_LIBZ
            if(session->current_crypto && session->current_crypto->do_compress_in){
                ssh_say(3,"Decompressing ...\n");
                decompress_buffer(session,session->in_buffer);
            }
#endif
            session->recv_seq++;
            session->packet_state=PACKET_STATE_INIT;
            return SSH_OK;
    }
    ssh_set_error(session,SSH_FATAL,"Invalid state into packet_read2() : %d",session->packet_state);
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
    ssh_say(3,"packet_read1()\n");
    if(!session->alive || session->data_except)
        return SSH_ERROR; // the error message was already set
    switch (session->packet_state){
        case PACKET_STATE_INIT:
            memset(&session->in_packet,0,sizeof(PACKET));
            if(session->in_buffer)
                buffer_reinit(session->in_buffer);
            else
                session->in_buffer=buffer_new();
            ret=socket_read(session,sizeof(u32));
            if(ret!=SSH_OK)
                return ret; // could be SSH_AGAIN
            buffer_get_u32(session->in_socket_buffer,&len);
            /*            be_read=completeread(session->fd,&len,sizeof(u32)); */
           /* len is not encrypted */
            len=ntohl(len); 
            if(len> MAX_PACKET_LEN){
                ssh_set_error(session,SSH_FATAL,"read_packet(): Packet len too high(%uld %.8lx)",len,len);
                return SSH_ERROR;
            }
            ssh_say(3,"%d bytes packet\n",len);
            session->in_packet.len=len;
            session->packet_state=PACKET_STATE_SIZEREAD;
        case PACKET_STATE_SIZEREAD:
            len=session->in_packet.len;
            /* SSH-1 has a fixed padding lenght */
            padding=8-(len % 8);
            to_be_read=len+padding;
            /* it is *not* possible that to_be_read be < 8. */
            ret=socket_read(session,to_be_read);
            if(ret != SSH_OK)
                return ret; // can be SSH_ERROR or SSH_AGAIN
            packet=malloc(to_be_read);
            memcpy(packet,buffer_get_rest(session->in_socket_buffer),to_be_read);
            buffer_pass_bytes(session->in_socket_buffer,to_be_read);
            buffer_add_data(session->in_buffer,packet,to_be_read);
            free(packet);
            
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("read packet:",buffer_get(session->in_buffer),
                buffer_get_len(session->in_buffer));
#endif
            if(session->current_crypto){
        /* we decrypt everything, missing the lenght part (which was previously
         * read, unencrypted, and is not part of the buffer
         */
                packet_decrypt(session,buffer_get(session->in_buffer),buffer_get_len(session->in_buffer));
            }
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("read packet decrypted:",
                           buffer_get(session->in_buffer),buffer_get_len(session->in_buffer));
#endif
            ssh_say(3,"%d bytes padding\n",padding);
            if((len+padding) != buffer_get_rest_len(session->in_buffer) || (len+padding) < sizeof(u32)){
                ssh_say(2,"no crc32 in packet\n");
                ssh_set_error(session,SSH_FATAL,"no crc32 in packet");
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
                ssh_say(2,"invalid crc32\n");
                ssh_set_error(session,SSH_FATAL,"invalid crc32 : expected %.8lx, "
                "got %.8lx",crc,
                ssh_crc32(buffer_get_rest(session->in_buffer),len+padding-sizeof(u32)) );
                return SSH_ERROR;
            }
            buffer_pass_bytes(session->in_buffer,padding);   /*pass the padding*/
            ssh_say(3,"the packet is valid\n");
/* will do that later 
#ifdef HAVE_LIBZ
    if(session->current_crypto && session->current_crypto->do_compress_in){
        decompress_buffer(session,session->in_buffer);
    }
#endif
*/
            session->recv_seq++;
            session->packet_state=PACKET_STATE_INIT;
            return SSH_OK;
    }
    ssh_set_error(session,SSH_FATAL,"Invalid state into packet_read2() : %d",session->packet_state);
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
    memset(&session->in_packet,0,sizeof(PACKET));
    if(!session->in_buffer)
        return -1;
    ssh_say(3,"Final size %d\n",buffer_get_rest_len(session->in_buffer));
    if(!buffer_get_u8(session->in_buffer,&session->in_packet.type)){
        ssh_set_error(session,SSH_FATAL,"Packet too short to read type");
        return -1;
    }
    ssh_say(3,"type %hhd\n",session->in_packet.type);
    session->in_packet.valid=1;
    return 0;
}

static int atomic_write(int fd, void *buffer, int len){
    int written;
    if(fd<0)
        return SSH_ERROR;
    while(len >0) {
        written=write(fd,buffer,len);
        if(written==0 || written==-1)
            return SSH_ERROR;
        len-=written;
        buffer+=written;
    }
    return SSH_OK;
}

/* when doing a nonblocking write, you should issue the packet_write only once, then 
 * do packet_nonblocking_flush() until you get a SSH_OK or a SSH_ERROR */
static int packet_nonblocking_flush(SSH_SESSION *session){
    int except, can_write;
    int w;
    ssh_fd_poll(session,&can_write,&except); /* internally sets data_to_write */
    if(session->fd<0){
        session->alive=0;
        ssh_set_error(session,SSH_FATAL,"Writing packet : error on socket (or connection closed): %s",strerror(errno));
        return SSH_ERROR;
    }
    while(session->data_to_write && buffer_get_rest_len(session->out_socket_buffer)>0){
        if(session->fd>=0){
            w=write(session->fd,buffer_get_rest(session->out_socket_buffer),
                buffer_get_rest_len(session->out_socket_buffer));
            session->data_to_write=0;
        } else
            w=-1; /* write failed */
        if(w<0){
            session->data_to_write=0;
            session->data_except=1;
            session->alive=0;
            close(session->fd);
            session->fd=-1;
            ssh_set_error(session,SSH_FATAL,"Writing packet : error on socket (or connection closed): %s",
                          strerror(errno));
            return SSH_ERROR;
        }
        buffer_pass_bytes(session->out_socket_buffer,w);
        /* refresh the socket status */
        ssh_fd_poll(session,&can_write,&except);
    }
    if(buffer_get_rest_len(session->out_socket_buffer)>0)
        return SSH_AGAIN;  /* there is data pending */
    return SSH_OK; // all data written
}

/* blocking packet flush */
static int packet_blocking_flush(SSH_SESSION *session){
    if(session->fd<0) {
        session->alive=0;
        return SSH_ERROR;
    }
    if(session->data_except)
        return SSH_ERROR;
    if(buffer_get_rest(session->out_socket_buffer)==0)
        return SSH_OK;
    if(atomic_write(session->fd,buffer_get_rest(session->out_socket_buffer),
       buffer_get_rest_len(session->out_socket_buffer))){
        session->data_to_write=0;
        session->data_except=1;
        session->alive=0;
        close(session->fd);
        session->fd=-1;
        ssh_set_error(session,SSH_FATAL,"Writing packet : error on socket (or connection closed): %s",
                         strerror(errno));
        return SSH_ERROR;
    }
    session->data_to_write=0;
    buffer_reinit(session->out_socket_buffer);
    return SSH_OK; // no data pending
}

/* Write the the bufferized output. If the session is blocking, or enforce_blocking 
 * is set, the call may block. Otherwise, it won't block.
 * return SSH°OK if everything has been sent, SSH_AGAIN if there are still things 
 * to send on buffer, SSH_ERROR if there is an error. */
int packet_flush(SSH_SESSION *session, int enforce_blocking){
    if(enforce_blocking || session->blocking)
        return packet_blocking_flush(session);
    return packet_nonblocking_flush(session);
}

/* this function places the outgoing packet buffer into an outgoing socket buffer */
static int socket_write(SSH_SESSION *session){
    if(!session->out_socket_buffer){
        session->out_socket_buffer=buffer_new();
    }
    buffer_add_data(session->out_socket_buffer,
               buffer_get(session->out_buffer),buffer_get_len(session->out_buffer));
    if(!session->blocking){
        return packet_nonblocking_flush(session);
    } else
        return packet_blocking_flush(session);
}

static int packet_send2(SSH_SESSION *session){
    char padstring[32];
    u32 finallen;
    u8 padding;
    u32 currentlen=buffer_get_len(session->out_buffer);
    unsigned char *hmac;
    int ret=0;
    unsigned int blocksize=(session->current_crypto?session->current_crypto->out_cipher->blocksize:8);
    ssh_say(3,"Writing on the wire a packet having %ld bytes before",currentlen);
#ifdef HAVE_LIBZ
    if(session->current_crypto && session->current_crypto->do_compress_out){
        ssh_say(3,"Compressing ...\n");
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
    ssh_say(3,",%d bytes after comp + %d padding bytes = %d bytes packet\n",currentlen,padding,(ntohl(finallen)));
    buffer_add_data_begin(session->out_buffer,&padding,sizeof(u8));
    buffer_add_data_begin(session->out_buffer,&finallen,sizeof(u32));
    buffer_add_data(session->out_buffer,padstring,padding);
    hmac=packet_encrypt(session,buffer_get(session->out_buffer),buffer_get_len(session->out_buffer));
    if(hmac)
        buffer_add_data(session->out_buffer,hmac,20);
    ret=socket_write(session);
    session->send_seq++;
    buffer_reinit(session->out_buffer);
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
    ssh_say(3,"Writing on the wire a packet having %ld bytes before",currentlen);
/*
#ifdef HAVE_LIBZ
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
    ssh_say(3,",%d bytes after comp + %d padding bytes = %d bytes packet\n",currentlen,padding,(ntohl(finallen)));
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
    ret=socket_write(session);
    session->send_seq++;
    buffer_reinit(session->out_buffer);
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
                ssh_say(2,"Received SSH_MSG_DISCONNECT\n");
                ssh_set_error(session,SSH_FATAL,"Received SSH_MSG_DISCONNECT");
                close(session->fd);
                session->fd=-1;
                session->alive=0;
                return;
            case SSH_SMSG_STDOUT_DATA:
            case SSH_SMSG_STDERR_DATA:
            case SSH_SMSG_EXITSTATUS:
                channel_handle1(session,type);
                return;
            default:
                ssh_say(2,"Unexpected message code %d\n",type);
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
            ssh_say(2,"Received SSH_MSG_DISCONNECT\n");
            ssh_set_error(session,SSH_FATAL,"Received SSH_MSG_DISCONNECT : %s",error);
            if(error_s){
                free(error_s);
                free(error);
            }
            close(session->fd);
            session->fd=-1;
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
            return;
        default:
            ssh_say(0,"Received unhandled msg %d\n",type);
    }
#ifdef HAVE_SSH1
    }
#endif
}    

#ifdef HAVE_SSH1
static int packet_wait1(SSH_SESSION *session,int type,int blocking){
    ssh_say(3,"packet_wait1 waiting for %d\n",type);
    while(1){
        if(packet_read1(session))
            return -1;
        if(packet_translate(session))
            return -1;
        ssh_say(3,"packet_wait 1 received %d\n",session->in_packet.type);
        switch(session->in_packet.type){
            case SSH_MSG_DISCONNECT:
                packet_parse(session);
                return -1;
            case SSH_SMSG_STDOUT_DATA:
            case SSH_SMSG_STDERR_DATA:
            case SSH_SMSG_EXITSTATUS:
                channel_handle1(session,type);
                break;
/*          case SSH2_MSG_CHANNEL_CLOSE:
               packet_parse(session);
                break;;
           case SSH2_MSG_IGNORE:
               break;
*/               
            default:
               if(type && (type != session->in_packet.type)){
                   ssh_set_error(session,SSH_FATAL,"waitpacket(): Received a %d type packet, was waiting for a %d\n",session->in_packet.type,type);
                   return -1;
               }
               return 0;
           }
        if(blocking==0)
            return 0;
    }
    return 0;
}
#endif /* HAVE_SSH1 */
static int packet_wait2(SSH_SESSION *session,int type,int blocking){
    int ret;
    while(1){
        ret=packet_read2(session);
        if(ret != SSH_OK)
            return ret;
        if(packet_translate(session))
            return SSH_ERROR;
        switch(session->in_packet.type){
           case SSH2_MSG_DISCONNECT:
               packet_parse(session);
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
                   return SSH_ERROR;
               }
               return SSH_OK;
           }
        if(blocking==0)
            return SSH_OK; //shouldn't it return SSH_AGAIN here ?
    }
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


void packet_clear_out(SSH_SESSION *session){
    if(session->out_buffer)
        buffer_reinit(session->out_buffer);
    else
        session->out_buffer=buffer_new();
}

