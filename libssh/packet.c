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
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/ssh1.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/packet.h"
#include "libssh/socket.h"
#include "libssh/channels.h"
#include "libssh/misc.h"
#include "libssh/session.h"
#include "libssh/messages.h"
#include "libssh/pcap.h"

ssh_packet_callback default_packet_handlers[]= {

	ssh_packet_disconnect_callback, //#define SSH2_MSG_DISCONNECT 1
	ssh_packet_ignore_callback, //#define SSH2_MSG_IGNORE	 2
	NULL, //#define SSH2_MSG_UNIMPLEMENTED 3
	ssh_packet_ignore_callback, //#define SSH2_MSG_DEBUG	4
	NULL, //#define SSH2_MSG_SERVICE_REQUEST	5
	NULL, //#define SSH2_MSG_SERVICE_ACCEPT 6
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, // 7-19
	NULL, //#define SSH2_MSG_KEXINIT	 20
	NULL, //#define SSH2_MSG_NEWKEYS 21
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, //22-29
	NULL, //#define SSH2_MSG_KEXDH_INIT 30 SSH2_MSG_KEX_DH_GEX_REQUEST_OLD 30
	NULL, // #define SSH2_MSG_KEXDH_REPLY 31 SSH2_MSG_KEX_DH_GEX_GROUP 31
	NULL, //#define SSH2_MSG_KEX_DH_GEX_INIT 32
	NULL, //#define SSH2_MSG_KEX_DH_GEX_REPLY 33
	NULL, //#define SSH2_MSG_KEX_DH_GEX_REQUEST 34
	NULL, NULL, NULL, NULL, NULL, // 35-49
	NULL,	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, //#define SSH2_MSG_USERAUTH_REQUEST 50
	NULL, //#define SSH2_MSG_USERAUTH_FAILURE 51
	NULL, //#define SSH2_MSG_USERAUTH_SUCCESS 52
	NULL, //#define SSH2_MSG_USERAUTH_BANNER 53
	NULL, //#define SSH2_MSG_USERAUTH_PK_OK 60 SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ 60
			//SSH2_MSG_USERAUTH_INFO_REQUEST	 60
	NULL, //#define SSH2_MSG_USERAUTH_INFO_RESPONSE 61
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, //62-79
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, //#define SSH2_MSG_GLOBAL_REQUEST 80
	NULL, //#define SSH2_MSG_REQUEST_SUCCESS 81
	NULL, //#define SSH2_MSG_REQUEST_FAILURE 82
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, // 83-89
	NULL, //#define SSH2_MSG_CHANNEL_OPEN 90
	NULL, //#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION 91
	NULL, //#define SSH2_MSG_CHANNEL_OPEN_FAILURE 92
	channel_rcv_change_window, //#define SSH2_MSG_CHANNEL_WINDOW_ADJUST 93
	channel_rcv_data, //#define SSH2_MSG_CHANNEL_DATA 94
	channel_rcv_data, //#define SSH2_MSG_CHANNEL_EXTENDED_DATA 95
	channel_rcv_eof, //#define SSH2_MSG_CHANNEL_EOF	96
	channel_rcv_close, //#define SSH2_MSG_CHANNEL_CLOSE 97
	channel_rcv_request, //#define SSH2_MSG_CHANNEL_REQUEST 98
	NULL, //#define SSH2_MSG_CHANNEL_SUCCESS 99
	NULL, //#define SSH2_MSG_CHANNEL_FAILURE 100
};

/* XXX include selected mac size */
static int macsize=SHA_DIGEST_LEN;

/* in nonblocking mode, socket_read will read as much as it can, and return */
/* SSH_OK if it has read at least len bytes, otherwise, SSH_AGAIN. */
/* in blocking mode, it will read at least len bytes and will block until it's ok. */


#define PACKET_STATE_INIT 0
#define PACKET_STATE_SIZEREAD 1
#define PACKET_STATE_PROCESSING 2

/** @internal
 * @handles a data received event. It then calls the handlers for the different packet types
 * or and exception handler callback.
 * @param user pointer to current ssh_session
 * @param data pointer to the data received
 * @len length of data received. It might not be enough for a complete packet
 * @returns number of bytes read and processed.
 */
int ssh_packet_socket_callback(const void *data, size_t receivedlen, void *user){
  ssh_session session=(ssh_session) user;
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->in_cipher->blocksize : 8);
  int current_macsize = session->current_crypto ? macsize : 0;
  unsigned char mac[30] = {0};
  char buffer[16] = {0};
  void *packet=NULL;
  int to_be_read;
  int rc = SSH_ERROR;
  uint32_t len;
  uint8_t padding;
  size_t processed=0; /* number of byte processed from the callback */

  enter_function();

  switch(session->packet_state) {
    case PACKET_STATE_INIT:
    	if(receivedlen < blocksize){
    		/* We didn't receive enough data to read at least one block size, give up */
    		leave_function();
    		return 0;
    	}
      memset(&session->in_packet, 0, sizeof(PACKET));

      if (session->in_buffer) {
        if (buffer_reinit(session->in_buffer) < 0) {
          goto error;
        }
      } else {
        session->in_buffer = buffer_new();
        if (session->in_buffer == NULL) {
          goto error;
        }
      }

      memcpy(buffer,data,blocksize);
      processed += blocksize;
      len = packet_decrypt_len(session, buffer);

      if (buffer_add_data(session->in_buffer, buffer, blocksize) < 0) {
        goto error;
      }

      if(len > MAX_PACKET_LEN) {
        ssh_set_error(session, SSH_FATAL,
            "read_packet(): Packet len too high(%u %.4x)", len, len);
        goto error;
      }

      to_be_read = len - blocksize + sizeof(uint32_t);
      if (to_be_read < 0) {
        /* remote sshd sends invalid sizes? */
        ssh_set_error(session, SSH_FATAL,
            "given numbers of bytes left to be read < 0 (%d)!", to_be_read);
        goto error;
      }

      /* saves the status of the current operations */
      session->in_packet.len = len;
      session->packet_state = PACKET_STATE_SIZEREAD;
    case PACKET_STATE_SIZEREAD:
      len = session->in_packet.len;
      to_be_read = len - blocksize + sizeof(uint32_t) + current_macsize;
      /* if to_be_read is zero, the whole packet was blocksize bytes. */
      if (to_be_read != 0) {
        if(receivedlen - processed < (unsigned int)to_be_read){
        	/* give up, not enough data in buffer */
        	return processed;
        }
        rc = SSH_ERROR;

        packet = (unsigned char *)data + processed;
//        ssh_socket_read(session->socket,packet,to_be_read-current_macsize);

        ssh_log(session,SSH_LOG_PACKET,"Read a %d bytes packet",len);

        if (buffer_add_data(session->in_buffer, packet,
              to_be_read - current_macsize) < 0) {
          goto error;
        }
        processed += to_be_read - current_macsize;
      }

      if (session->current_crypto) {
        /*
         * decrypt the rest of the packet (blocksize bytes already
         * have been decrypted)
         */
        if (packet_decrypt(session,
              ((uint8_t*)buffer_get(session->in_buffer) + blocksize),
              buffer_get_len(session->in_buffer) - blocksize) < 0) {
          ssh_set_error(session, SSH_FATAL, "Decrypt error");
          goto error;
        }
        /* copy the last part from the incoming buffer */
        memcpy(mac,(unsigned char *)packet + to_be_read - current_macsize, macsize);

        if (packet_hmac_verify(session, session->in_buffer, mac) < 0) {
          ssh_set_error(session, SSH_FATAL, "HMAC error");
          goto error;
        }
      }

      /* skip the size field which has been processed before */
      buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));

      if (buffer_get_u8(session->in_buffer, &padding) == 0) {
        ssh_set_error(session, SSH_FATAL, "Packet too short to read padding");
        goto error;
      }

      ssh_log(session, SSH_LOG_PACKET,
          "%hhd bytes padding, %d bytes left in buffer",
          padding, buffer_get_rest_len(session->in_buffer));

      if (padding > buffer_get_rest_len(session->in_buffer)) {
        ssh_set_error(session, SSH_FATAL,
            "Invalid padding: %d (%d resting)",
            padding,
            buffer_get_rest_len(session->in_buffer));
#ifdef DEBUG_CRYPTO
        ssh_print_hexa("incrimined packet",
            buffer_get(session->in_buffer),
            buffer_get_len(session->in_buffer));
#endif
        goto error;
      }
      buffer_pass_bytes_end(session->in_buffer, padding);

      ssh_log(session, SSH_LOG_PACKET,
          "After padding, %d bytes left in buffer",
          buffer_get_rest_len(session->in_buffer));
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
      if (session->current_crypto && session->current_crypto->do_compress_in) {
        ssh_log(session, SSH_LOG_PACKET, "Decompressing in_buffer ...");
        if (decompress_buffer(session, session->in_buffer,MAX_PACKET_LEN) < 0) {
          goto error;
        }
      }
#endif
      session->recv_seq++;
      /* We don't want to rewrite a new packet while still executing the packet callbacks */
      session->packet_state = PACKET_STATE_PROCESSING;
      packet_translate(session);
      /* execute callbacks */
      ssh_packet_process(session, session->in_packet.type);
      session->packet_state = PACKET_STATE_INIT;
      leave_function();
      return processed;
    case PACKET_STATE_PROCESSING:
    	ssh_log(session, SSH_LOG_PACKET, "Nested packet processing. Delaying.");
    	return 0;
  }

  ssh_set_error(session, SSH_FATAL,
      "Invalid state into packet_read2(): %d",
      session->packet_state);

error:
  leave_function();
  return processed;
}

void ssh_packet_register_socket_callback(ssh_session session, ssh_socket s){
	session->socket_callbacks.data=ssh_packet_socket_callback;
	session->socket_callbacks.connected=NULL;
	session->socket_callbacks.controlflow=NULL;
	session->socket_callbacks.exception=NULL;
	session->socket_callbacks.user=session;
	ssh_socket_set_callbacks(s,&session->socket_callbacks);
}

/** @internal
 * @brief sets the callbacks for the packet layer
 */
void ssh_packet_set_callbacks(ssh_session session, ssh_packet_callbacks callbacks){
	if(session->packet_callbacks == NULL){
		session->packet_callbacks = ssh_list_new();
	}
	ssh_list_add(session->packet_callbacks,callbacks);
}

/** @internal
 * @brief sets the default packet handlers
 */
void ssh_packet_set_default_callbacks(ssh_session session){
	session->default_packet_callbacks.start=0;
	session->default_packet_callbacks.n_callbacks=sizeof(default_packet_handlers)/sizeof(ssh_packet_callback);
	session->default_packet_callbacks.user=session;
	session->default_packet_callbacks.callbacks=default_packet_handlers;
	ssh_packet_set_callbacks(session, &session->default_packet_callbacks);
}

/** @internal
 * @brief dispatch the call of packet handlers callbacks for a received packet
 * @param type type of packet
 */
void ssh_packet_process(ssh_session session, uint8_t type){
	struct ssh_iterator *i;
	int r;
	ssh_packet_callbacks cb;
	enter_function();
	ssh_log(session,SSH_LOG_PACKET, "Dispatching handler for packet type %d",type);
	if(session->packet_callbacks == NULL){
		ssh_log(session,SSH_LOG_RARE,"Packet callback is not initialized !");
		goto error;
	}
	i=ssh_list_get_iterator(session->packet_callbacks);
	while(i != NULL){
		cb=ssh_iterator_value(ssh_packet_callbacks,i);
		i=i->next;
		if(!cb)
			continue;
		if(cb->start > type)
			continue;
		if(cb->start + cb->n_callbacks > type)
			continue;
		if(cb->callbacks[type - cb->start]==NULL)
			continue;
		r=cb->callbacks[type - cb->start](session,type,session->in_buffer,cb->user);
		if(r==SSH_PACKET_USED)
			break;
	}
error:
	leave_function();
}

static int packet_read2(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->in_cipher->blocksize : 8);
  int current_macsize = session->current_crypto ? macsize : 0;
  unsigned char mac[30] = {0};
  char buffer[16] = {0};
  void *packet=NULL;
  int to_be_read;
  int rc = SSH_ERROR;

  uint32_t len;
  uint8_t padding;

  enter_function();

  if (session->alive == 0) {
    /* The error message was already set into this session */
    leave_function();
    return SSH_ERROR;
  }

  switch(session->packet_state) {
    case PACKET_STATE_INIT:
      memset(&session->in_packet, 0, sizeof(PACKET));

      if (session->in_buffer) {
        if (buffer_reinit(session->in_buffer) < 0) {
          goto error;
        }
      } else {
        session->in_buffer = buffer_new();
        if (session->in_buffer == NULL) {
          goto error;
        }
      }

      rc = ssh_socket_wait_for_data(session->socket, session, blocksize);
      if (rc != SSH_OK) {
        goto error;
      }
      rc = SSH_ERROR;
      /* can't fail since we're sure there is enough data in socket buffer */
      ssh_socket_read(session->socket, buffer, blocksize);
      len = packet_decrypt_len(session, buffer);

      if (buffer_add_data(session->in_buffer, buffer, blocksize) < 0) {
        goto error;
      }

      if(len > MAX_PACKET_LEN) {
        ssh_set_error(session, SSH_FATAL,
            "read_packet(): Packet len too high(%u %.4x)", len, len);
        goto error;
      }

      to_be_read = len - blocksize + sizeof(uint32_t);
      if (to_be_read < 0) {
        /* remote sshd sends invalid sizes? */
        ssh_set_error(session, SSH_FATAL,
            "given numbers of bytes left to be read < 0 (%d)!", to_be_read);
        goto error;
      }

      /* saves the status of the current operations */
      session->in_packet.len = len;
      session->packet_state = PACKET_STATE_SIZEREAD;
    case PACKET_STATE_SIZEREAD:
      len = session->in_packet.len;
      to_be_read = len - blocksize + sizeof(uint32_t) + current_macsize;
      /* if to_be_read is zero, the whole packet was blocksize bytes. */
      if (to_be_read != 0) {
        rc = ssh_socket_wait_for_data(session->socket,session,to_be_read);
        if (rc != SSH_OK) {
          goto error;
        }
        rc = SSH_ERROR;

        packet = malloc(to_be_read);
        if (packet == NULL) {
          ssh_set_error(session, SSH_FATAL, "No space left");
          goto error;
        }
        ssh_socket_read(session->socket,packet,to_be_read-current_macsize);

        ssh_log(session,SSH_LOG_PACKET,"Read a %d bytes packet",len);

        if (buffer_add_data(session->in_buffer, packet,
              to_be_read - current_macsize) < 0) {
          SAFE_FREE(packet);
          goto error;
        }
        SAFE_FREE(packet);
      }

      if (session->current_crypto) {
        /*
         * decrypt the rest of the packet (blocksize bytes already
         * have been decrypted)
         */
        if (packet_decrypt(session,
              ((uint8_t*)buffer_get(session->in_buffer) + blocksize),
              buffer_get_len(session->in_buffer) - blocksize) < 0) {
          ssh_set_error(session, SSH_FATAL, "Decrypt error");
          goto error;
        }
#ifdef WITH_PCAP
        if(session->pcap_ctx){
        	ssh_pcap_context_write(session->pcap_ctx,
        			SSH_PCAP_DIR_IN, buffer_get(session->in_buffer),
        			buffer_get_len(session->in_buffer),
        			buffer_get_len(session->in_buffer));
        }
#endif
        ssh_socket_read(session->socket, mac, macsize);

        if (packet_hmac_verify(session, session->in_buffer, mac) < 0) {
          ssh_set_error(session, SSH_FATAL, "HMAC error");
          goto error;
        }
      }
#ifdef WITH_PCAP
      else {
      	/* No crypto */
        if(session->pcap_ctx){
        	ssh_pcap_context_write(session->pcap_ctx,
        			SSH_PCAP_DIR_IN, buffer_get(session->in_buffer),
        			buffer_get_len(session->in_buffer),
        			buffer_get_len(session->in_buffer));
        }
      }
#endif

      buffer_pass_bytes(session->in_buffer, sizeof(uint32_t));

      /* pass the size which has been processed before */
      if (buffer_get_u8(session->in_buffer, &padding) == 0) {
        ssh_set_error(session, SSH_FATAL, "Packet too short to read padding");
        goto error;
      }

      ssh_log(session, SSH_LOG_PACKET,
          "%hhd bytes padding, %d bytes left in buffer",
          padding, buffer_get_rest_len(session->in_buffer));

      if (padding > buffer_get_rest_len(session->in_buffer)) {
        ssh_set_error(session, SSH_FATAL,
            "Invalid padding: %d (%d resting)",
            padding,
            buffer_get_rest_len(session->in_buffer));
#ifdef DEBUG_CRYPTO
        ssh_print_hexa("incrimined packet",
            buffer_get(session->in_buffer),
            buffer_get_len(session->in_buffer));
#endif
        goto error;
      }
      buffer_pass_bytes_end(session->in_buffer, padding);

      ssh_log(session, SSH_LOG_PACKET,
          "After padding, %d bytes left in buffer",
          buffer_get_rest_len(session->in_buffer));
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
      if (session->current_crypto && session->current_crypto->do_compress_in) {
        ssh_log(session, SSH_LOG_PACKET, "Decompressing in_buffer ...");
        if (decompress_buffer(session, session->in_buffer, MAX_PACKET_LEN) < 0) {
          goto error;
        }
      }
#endif
      session->recv_seq++;
      session->packet_state = PACKET_STATE_INIT;

      leave_function();
      return SSH_OK;
  }

  ssh_set_error(session, SSH_FATAL,
      "Invalid state into packet_read2(): %d",
      session->packet_state);

error:
  leave_function();
  return rc;
}

#ifdef WITH_SSH1
/* a slighty modified packet_read2() for SSH-1 protocol */
static int packet_read1(ssh_session session) {
  void *packet = NULL;
  int rc = SSH_ERROR;
  int to_be_read;
  uint32_t padding;
  uint32_t crc;
  uint32_t len;

  enter_function();

  if(!session->alive) {
    goto error;
  }

  switch (session->packet_state){
    case PACKET_STATE_INIT:
      memset(&session->in_packet, 0, sizeof(PACKET));

      if (session->in_buffer) {
        if (buffer_reinit(session->in_buffer) < 0) {
          goto error;
        }
      } else {
        session->in_buffer = buffer_new();
        if (session->in_buffer == NULL) {
          goto error;
        }
      }

      rc = ssh_socket_read(session->ssh_socket_struct, &len, sizeof(uint32_t));
      if (rc != SSH_OK) {
        goto error;
      }

      rc = SSH_ERROR;

      /* len is not encrypted */
      len = ntohl(len);
      if (len > MAX_PACKET_LEN) {
        ssh_set_error(session, SSH_FATAL,
            "read_packet(): Packet len too high (%u %.8x)", len, len);
        goto error;
      }

      ssh_log(session, SSH_LOG_PACKET, "Reading a %d bytes packet", len);

      session->in_packet.len = len;
      session->packet_state = PACKET_STATE_SIZEREAD;
    case PACKET_STATE_SIZEREAD:
      len = session->in_packet.len;
      /* SSH-1 has a fixed padding lenght */
      padding = 8 - (len % 8);
      to_be_read = len + padding;

      /* it is _not_ possible that to_be_read be < 8. */
      packet = malloc(to_be_read);
      if (packet == NULL) {
        ssh_set_error(session, SSH_FATAL, "Not enough space");
        goto error;
      }

      rc = ssh_socket_read(session->ssh_socket_struct, packet, to_be_read);
      if(rc != SSH_OK) {
        SAFE_FREE(packet);
        goto error;
      }
      rc = SSH_ERROR;

      if (buffer_add_data(session->in_buffer,packet,to_be_read) < 0) {
        SAFE_FREE(packet);
        goto error;
      }
      SAFE_FREE(packet);

#ifdef DEBUG_CRYPTO
      ssh_print_hexa("read packet:", buffer_get(session->in_buffer),
          buffer_get_len(session->in_buffer));
#endif
      if (session->current_crypto) {
        /*
         * We decrypt everything, missing the lenght part (which was
         * previously read, unencrypted, and is not part of the buffer
         */
        if (packet_decrypt(session,
              buffer_get(session->in_buffer),
              buffer_get_len(session->in_buffer)) < 0) {
          ssh_set_error(session, SSH_FATAL, "Packet decrypt error");
          goto error;
        }
      }
#ifdef DEBUG_CRYPTO
      ssh_print_hexa("read packet decrypted:", buffer_get(session->in_buffer),
          buffer_get_len(session->in_buffer));
#endif
      ssh_log(session, SSH_LOG_PACKET, "%d bytes padding", padding);
      if(((len + padding) != buffer_get_rest_len(session->in_buffer)) ||
          ((len + padding) < sizeof(uint32_t))) {
        ssh_log(session, SSH_LOG_RARE, "no crc32 in packet");
        ssh_set_error(session, SSH_FATAL, "no crc32 in packet");
        goto error;
      }

      memcpy(&crc,
          (unsigned char *)buffer_get_rest(session->in_buffer) + (len+padding) - sizeof(uint32_t),
          sizeof(uint32_t));
      buffer_pass_bytes_end(session->in_buffer, sizeof(uint32_t));
      crc = ntohl(crc);
      if (ssh_crc32(buffer_get_rest(session->in_buffer),
            (len + padding) - sizeof(uint32_t)) != crc) {
#ifdef DEBUG_CRYPTO
        ssh_print_hexa("crc32 on",buffer_get_rest(session->in_buffer),
            len + padding - sizeof(uint32_t));
#endif
        ssh_log(session, SSH_LOG_RARE, "Invalid crc32");
        ssh_set_error(session, SSH_FATAL,
            "Invalid crc32: expected %.8x, got %.8x",
            crc,
            ssh_crc32(buffer_get_rest(session->in_buffer),
              len + padding - sizeof(uint32_t)));
        goto error;
      }
      /* pass the padding */
      buffer_pass_bytes(session->in_buffer, padding);
      ssh_log(session, SSH_LOG_PACKET, "The packet is valid");

/* TODO FIXME
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
  } /* switch */

  ssh_set_error(session, SSH_FATAL,
      "Invalid state into packet_read1(): %d",
      session->packet_state);
error:
  leave_function();
  return rc;
}

#endif /* WITH_SSH1 */

/* that's where i'd like C to be object ... */
int packet_read(ssh_session session) {
#ifdef WITH_SSH1
  if (session->version == 1) {
    return packet_read1(session);
  }
#endif
  return packet_read2(session);
}

int packet_translate(ssh_session session) {
  enter_function();

  memset(&session->in_packet, 0, sizeof(PACKET));
  if(session->in_buffer == NULL) {
    leave_function();
    return SSH_ERROR;
  }

  ssh_log(session, SSH_LOG_PACKET, "Final size %d",
      buffer_get_rest_len(session->in_buffer));

  if(buffer_get_u8(session->in_buffer, &session->in_packet.type) == 0) {
    ssh_set_error(session, SSH_FATAL, "Packet too short to read type");
    leave_function();
    return SSH_ERROR;
  }

  ssh_log(session, SSH_LOG_PACKET, "Type %hhd", session->in_packet.type);
  session->in_packet.valid = 1;

  leave_function();
  return SSH_OK;
}

/*
 * Write the the bufferized output. If the session is blocking, or
 * enforce_blocking is set, the call may block. Otherwise, it won't block.
 * Return SSH_OK if everything has been sent, SSH_AGAIN if there are still
 * things to send on buffer, SSH_ERROR if there is an error.
 */
int packet_flush(ssh_session session, int enforce_blocking) {
  if (enforce_blocking || session->blocking) {
    return ssh_socket_blocking_flush(session->socket);
  }

  return ssh_socket_nonblocking_flush(session->socket);
}

/*
 * This function places the outgoing packet buffer into an outgoing
 * socket buffer
 */
static int packet_write(ssh_session session) {
  int rc = SSH_ERROR;

  enter_function();

  ssh_socket_write(session->socket,
      buffer_get(session->out_buffer),
      buffer_get_len(session->out_buffer));

  rc = packet_flush(session, 0);

  leave_function();
  return rc;
}

static int packet_send2(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->blocksize : 8);
  uint32_t currentlen = buffer_get_len(session->out_buffer);
  unsigned char *hmac = NULL;
  char padstring[32] = {0};
  int rc = SSH_ERROR;
  uint32_t finallen;
  uint8_t padding;

  enter_function();

  ssh_log(session, SSH_LOG_PACKET,
      "Writing on the wire a packet having %u bytes before", currentlen);

#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
  if (session->current_crypto && session->current_crypto->do_compress_out) {
    ssh_log(session, SSH_LOG_PACKET, "Compressing in_buffer ...");
    if (compress_buffer(session,session->out_buffer) < 0) {
      goto error;
    }
    currentlen = buffer_get_len(session->out_buffer);
  }
#endif
  padding = (blocksize - ((currentlen +5) % blocksize));
  if(padding < 4) {
    padding += blocksize;
  }

  if (session->current_crypto) {
    ssh_get_random(padstring, padding, 0);
  } else {
    memset(padstring,0,padding);
  }

  finallen = htonl(currentlen + padding + 1);
  ssh_log(session, SSH_LOG_PACKET,
      "%d bytes after comp + %d padding bytes = %lu bytes packet",
      currentlen, padding, (long unsigned int) ntohl(finallen));

  if (buffer_prepend_data(session->out_buffer, &padding, sizeof(uint8_t)) < 0) {
    goto error;
  }
  if (buffer_prepend_data(session->out_buffer, &finallen, sizeof(uint32_t)) < 0) {
    goto error;
  }
  if (buffer_add_data(session->out_buffer, padstring, padding) < 0) {
    goto error;
  }
#ifdef WITH_PCAP
  if(session->pcap_ctx){
  	ssh_pcap_context_write(session->pcap_ctx,SSH_PCAP_DIR_OUT,
  			buffer_get(session->out_buffer),buffer_get_len(session->out_buffer)
  			,buffer_get_len(session->out_buffer));
  }
#endif
  hmac = packet_encrypt(session, buffer_get(session->out_buffer),
      buffer_get_len(session->out_buffer));
  if (hmac) {
    if (buffer_add_data(session->out_buffer, hmac, 20) < 0) {
      goto error;
    }
  }

  rc = packet_write(session);
  session->send_seq++;

  if (buffer_reinit(session->out_buffer) < 0) {
    rc = SSH_ERROR;
  }
error:
  leave_function();
  return rc; /* SSH_OK, AGAIN or ERROR */
}

#ifdef WITH_SSH1
static int packet_send1(ssh_session session) {
  unsigned int blocksize = (session->current_crypto ?
      session->current_crypto->out_cipher->blocksize : 8);
  uint32_t currentlen = buffer_get_len(session->out_buffer) + sizeof(uint32_t);
  char padstring[32] = {0};
  int rc = SSH_ERROR;
  uint32_t finallen;
  uint32_t crc;
  uint8_t padding;

  enter_function();
  ssh_log(session,SSH_LOG_PACKET,"Sending a %d bytes long packet",currentlen);

/* TODO FIXME
#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
  if (session->current_crypto && session->current_crypto->do_compress_out) {
    if (compress_buffer(session, session->out_buffer) < 0) {
      goto error;
    }
    currentlen = buffer_get_len(session->out_buffer);
  }
#endif
*/
  padding = blocksize - (currentlen % blocksize);
  if (session->current_crypto) {
    ssh_get_random(padstring, padding, 0);
  } else {
    memset(padstring, 0, padding);
  }

  finallen = htonl(currentlen);
  ssh_log(session, SSH_LOG_PACKET,
      "%d bytes after comp + %d padding bytes = %d bytes packet",
      currentlen, padding, ntohl(finallen));

  if (buffer_prepend_data(session->out_buffer, &padstring, padding) < 0) {
    goto error;
  }
  if (buffer_prepend_data(session->out_buffer, &finallen, sizeof(uint32_t)) < 0) {
    goto error;
  }

  crc = ssh_crc32((char *)buffer_get(session->out_buffer) + sizeof(uint32_t),
      buffer_get_len(session->out_buffer) - sizeof(uint32_t));

  if (buffer_add_u32(session->out_buffer, ntohl(crc)) < 0) {
    goto error;
  }

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Clear packet", buffer_get(session->out_buffer),
      buffer_get_len(session->out_buffer));
#endif

  packet_encrypt(session, (unsigned char *)buffer_get(session->out_buffer) + sizeof(uint32_t),
      buffer_get_len(session->out_buffer) - sizeof(uint32_t));

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("encrypted packet",buffer_get(session->out_buffer),
      buffer_get_len(session->out_buffer));
#endif
  if (ssh_socket_write(session->ssh_socket_struct, buffer_get(session->out_buffer),
      buffer_get_len(session->out_buffer)) == SSH_ERROR) {
    goto error;
  }

  rc = packet_flush(session, 0);
  session->send_seq++;

  if (buffer_reinit(session->out_buffer) < 0) {
    rc = SSH_ERROR;
  }
error:
  leave_function();
  return rc;     /* SSH_OK, AGAIN or ERROR */
}

#endif /* WITH_SSH1 */

int packet_send(ssh_session session) {
#ifdef WITH_SSH1
  if (session->version == 1) {
    return packet_send1(session);
  }
#endif
  return packet_send2(session);
}

void packet_parse(ssh_session session) {
  uint8_t type = session->in_packet.type;

#ifdef WITH_SSH1
  if (session->version == 1) {
    /* SSH-1 */
    switch(type) {
      case SSH_MSG_DISCONNECT:
        ssh_log(session, SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT");
        ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_DISCONNECT");

        ssh_socket_close(session->ssh_socket_struct);
        session->alive = 0;
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
#endif /* WITH_SSH1 */
    switch(type) {
      case SSH2_MSG_DISCONNECT:
      case SSH2_MSG_CHANNEL_WINDOW_ADJUST:
      case SSH2_MSG_CHANNEL_DATA:
      case SSH2_MSG_CHANNEL_EXTENDED_DATA:
      case SSH2_MSG_CHANNEL_REQUEST:
      case SSH2_MSG_CHANNEL_EOF:
      case SSH2_MSG_CHANNEL_CLOSE:
      case SSH2_MSG_IGNORE:
      case SSH2_MSG_DEBUG:
        ssh_packet_process(session,type);
        return;
      case SSH2_MSG_SERVICE_REQUEST:
      case SSH2_MSG_USERAUTH_REQUEST:
      case SSH2_MSG_CHANNEL_OPEN:
        message_handle(session,NULL,type,session->in_buffer);
        return;
      default:
        ssh_log(session, SSH_LOG_RARE, "Received unhandled packet %d", type);
    }
#ifdef WITH_SSH1
  }
#endif
}

#ifdef WITH_SSH1
static int packet_wait1(ssh_session session, int type, int blocking) {

  enter_function();

  ssh_log(session, SSH_LOG_PROTOCOL, "packet_wait1 waiting for %d", type);

  do {
    if ((packet_read1(session) != SSH_OK) ||
        (packet_translate(session) != SSH_OK)) {
      leave_function();
      return SSH_ERROR;
    }
    ssh_log(session, SSH_LOG_PACKET, "packet_wait1() received a type %d packet",
        session->in_packet.type);
    switch (session->in_packet.type) {
      case SSH_MSG_DISCONNECT:
        packet_parse(session);
        leave_function();
        return SSH_ERROR;
      case SSH_SMSG_STDOUT_DATA:
      case SSH_SMSG_STDERR_DATA:
      case SSH_SMSG_EXITSTATUS:
        if (channel_handle1(session,type) < 0) {
          leave_function();
          return SSH_ERROR;
        }
        break;
      case SSH_MSG_DEBUG:
      case SSH_MSG_IGNORE:
        break;
        /*          case SSH2_MSG_CHANNEL_CLOSE:
                    packet_parse(session);
                    break;;
                    */
      default:
        if (type && (type != session->in_packet.type)) {
          ssh_set_error(session, SSH_FATAL,
              "packet_wait1(): Received a %d type packet, but expected %d\n",
              session->in_packet.type, type);
          leave_function();
          return SSH_ERROR;
        }
        leave_function();
        return SSH_OK;
    }

    if (blocking == 0) {
      leave_function();
      return SSH_OK;
    }
  } while(1);

  leave_function();
  return SSH_OK;
}
#endif /* WITH_SSH1 */

static int packet_wait2(ssh_session session, int type, int blocking) {
  int rc = SSH_ERROR;

  enter_function();
  do {
    rc = packet_read2(session);
    if (rc != SSH_OK) {
      leave_function();
      return rc;
    }
    if (packet_translate(session) != SSH_OK) {
      leave_function();
      return SSH_ERROR;
    }
    switch (session->in_packet.type) {
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
      case SSH2_MSG_SERVICE_REQUEST:
      case SSH2_MSG_USERAUTH_REQUEST:
      case SSH2_MSG_CHANNEL_OPEN:
        packet_parse(session);
        break;
      case SSH2_MSG_IGNORE:
      case SSH2_MSG_DEBUG:
        break;
      default:
        if (type && (type != session->in_packet.type)) {
          ssh_set_error(session, SSH_FATAL,
              "packet_wait2(): Received a %d type packet, but expected a %d\n",
              session->in_packet.type, type);
          leave_function();
          return SSH_ERROR;
        }
        leave_function();
        return SSH_OK;
    }
    if (blocking == 0) {
      leave_function();
      return SSH_OK; //shouldn't it return SSH_AGAIN here ?
    }
  } while(1);

  leave_function();
  return SSH_OK;
}

int packet_wait(ssh_session session, int type, int block) {
#ifdef WITH_SSH1
  if (session->version == 1) {
    return packet_wait1(session, type, block);
  }
#endif
  return packet_wait2(session, type, block);
}

/* vim: set ts=2 sw=2 et cindent: */
