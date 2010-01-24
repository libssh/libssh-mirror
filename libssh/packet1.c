/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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
#include "libssh/priv.h"
#include "libssh/ssh1.h"
#include "libssh/packet.h"
#include "libssh/session.h"
#include "libssh/buffer.h"
#include "libssh/socket.h"
#include "libssh/kex.h"
#ifdef WITH_SSH1

ssh_packet_callback default_packet_handlers1[]= {
  NULL,                           //SSH_MSG_NONE                        0
  ssh_packet_disconnect1,         //SSH_MSG_DISCONNECT                  1
  ssh_packet_publickey1,          //SSH_SMSG_PUBLIC_KEY                 2
  NULL,                           //SSH_CMSG_SESSION_KEY                3
  NULL,                           //SSH_CMSG_USER                       4
  NULL,                           //SSH_CMSG_AUTH_RHOSTS                5
  NULL,                           //SSH_CMSG_AUTH_RSA                   6
  NULL,                           //SSH_SMSG_AUTH_RSA_CHALLENGE         7
  NULL,                           //SSH_CMSG_AUTH_RSA_RESPONSE          8
  NULL,                           //SSH_CMSG_AUTH_PASSWORD              9
  NULL,                           //SSH_CMSG_REQUEST_PTY                10
  NULL,                           //SSH_CMSG_WINDOW_SIZE                11
  NULL,                           //SSH_CMSG_EXEC_SHELL                 12
  NULL,                           //SSH_CMSG_EXEC_CMD                   13
  ssh_packet_smsg_success1,       //SSH_SMSG_SUCCESS                    14
  ssh_packet_smsg_failure1,       //SSH_SMSG_FAILURE                    15
  NULL,                           //SSH_CMSG_STDIN_DATA                 16
  ssh_packet_data1,               //SSH_SMSG_STDOUT_DATA                17
  ssh_packet_data1,               //SSH_SMSG_STDERR_DATA                18
  NULL,                           //SSH_CMSG_EOF                        19
  NULL,                           //SSH_SMSG_EXITSTATUS                 20
  NULL,                           //SSH_MSG_CHANNEL_OPEN_CONFIRMATION   21
  NULL,                           //SSH_MSG_CHANNEL_OPEN_FAILURE        22
  NULL,                           //SSH_MSG_CHANNEL_DATA                23
  ssh_packet_close1,              //SSH_MSG_CHANNEL_CLOSE               24
  NULL,                           //SSH_MSG_CHANNEL_CLOSE_CONFIRMATION  25
  NULL,                           //SSH_CMSG_X11_REQUEST_FORWARDING     26
  NULL,                           //SSH_SMSG_X11_OPEN                   27
  NULL,                           //SSH_CMSG_PORT_FORWARD_REQUEST       28
  NULL,                           //SSH_MSG_PORT_OPEN                   29
  NULL,                           //SSH_CMSG_AGENT_REQUEST_FORWARDING   30
  NULL,                           //SSH_SMSG_AGENT_OPEN                 31
  ssh_packet_ignore_callback,     //SSH_MSG_IGNORE                      32
  NULL,                           //SSH_CMSG_EXIT_CONFIRMATION          33
  NULL,                           //SSH_CMSG_X11_REQUEST_FORWARDING     34
  NULL,                           //SSH_CMSG_AUTH_RHOSTS_RSA            35
  ssh_packet_ignore_callback,     //SSH_MSG_DEBUG                       36
};

/** @internal
 * @brief sets the default packet handlers
 */
void ssh_packet_set_default_callbacks1(ssh_session session){
  session->default_packet_callbacks.start=1;
  session->default_packet_callbacks.n_callbacks=sizeof(default_packet_handlers1)/sizeof(ssh_packet_callback);
  session->default_packet_callbacks.user=session;
  session->default_packet_callbacks.callbacks=default_packet_handlers1;
  ssh_packet_set_callbacks(session, &session->default_packet_callbacks);
}

/* a slightly modified packet_read2() for SSH-1 protocol
 * TODO: should be transformed in an asynchronous socket callback
 */
int packet_read(ssh_session session) {
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

      rc = ssh_socket_read(session->socket, &len, sizeof(uint32_t));
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

      rc = ssh_socket_read(session->socket, packet, to_be_read);
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


int packet_send1(ssh_session session) {
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
  if (ssh_socket_write(session->socket, buffer_get(session->out_buffer),
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

SSH_PACKET_CALLBACK(ssh_packet_disconnect1){
  (void)packet;
  (void)user;
  (void)type;
  ssh_log(session, SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT");
  ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_DISCONNECT");
  ssh_socket_close(session->socket);
  session->alive = 0;
  return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_smsg_success1){
  if(session->session_state==SSH_SESSION_STATE_KEXINIT_RECEIVED){
    session->session_state=SSH_SESSION_STATE_AUTHENTICATING;
    return SSH_PACKET_USED;
  } else if(session->session_state==SSH_SESSION_STATE_AUTHENTICATING){
    ssh_auth1_handler(session,type);
    return SSH_PACKET_USED;
  } else {
    return ssh_packet_channel_success(session,type,packet,user);
  }
}

SSH_PACKET_CALLBACK(ssh_packet_smsg_failure1){
  if(session->session_state==SSH_SESSION_STATE_KEXINIT_RECEIVED){
    session->session_state=SSH_SESSION_STATE_ERROR;
    ssh_set_error(session,SSH_FATAL,"Key exchange failed: received SSH_SMSG_FAILURE");
    return SSH_PACKET_USED;
  } else if(session->session_state==SSH_SESSION_STATE_AUTHENTICATING){
    ssh_auth1_handler(session,type);
    return SSH_PACKET_USED;
  } else {
    return ssh_packet_channel_failure(session,type,packet,user);
  }
}


#endif /* WITH_SSH1 */

/* vim: set ts=2 sw=2 et cindent: */
