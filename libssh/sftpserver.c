/*
 * sftpserver.c - server based function for the sftp protocol
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005      by Aris Adamantiadis
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libssh/libssh.h"
#include "libssh/sftp.h"
#include "libssh/ssh2.h"
#include "libssh/priv.h"

SFTP_CLIENT_MESSAGE *sftp_get_client_message(SFTP_SESSION *sftp) {
  SFTP_PACKET *packet;
  SFTP_CLIENT_MESSAGE *msg;
  BUFFER *payload;
  STRING *tmp;

  msg = malloc(sizeof (SFTP_CLIENT_MESSAGE));
  if (msg == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(msg);

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    sftp_client_message_free(msg);
    return NULL;
  }

  payload = packet->payload;
  msg->type = packet->type;
  msg->sftp = sftp;

  buffer_get_u32(payload, &msg->id);

  switch(msg->type) {
    case SSH_FXP_CLOSE:
    case SSH_FXP_READDIR:
      msg->handle = buffer_get_ssh_string(payload);
      if (msg->handle == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_READ:
      msg->handle = buffer_get_ssh_string(payload);
      if (msg->handle == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      buffer_get_u64(payload, &msg->offset);
      buffer_get_u32(payload, &msg->len);
      break;
    case SSH_FXP_WRITE:
      msg->handle = buffer_get_ssh_string(payload);
      if (msg->handle == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      buffer_get_u64(payload, &msg->offset);
      msg->data = buffer_get_ssh_string(payload);
      if (msg->data == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_REMOVE:
    case SSH_FXP_RMDIR:
    case SSH_FXP_OPENDIR:
    case SSH_FXP_READLINK:
    case SSH_FXP_REALPATH:
      tmp = buffer_get_ssh_string(payload);
      if (tmp == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->filename = string_to_char(tmp);
      string_free(tmp);
      if (msg->filename == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_RENAME:
    case SSH_FXP_SYMLINK:
      tmp = buffer_get_ssh_string(payload);
      if (tmp == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->filename = string_to_char(tmp);
      string_free(tmp);
      if (msg->filename == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->data = buffer_get_ssh_string(payload);
      if (msg->data == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_MKDIR:
    case SSH_FXP_SETSTAT:
      tmp = buffer_get_ssh_string(payload);
      if (tmp == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->filename=string_to_char(tmp);
      string_free(tmp);
      if (msg->filename == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->attr = sftp_parse_attr(sftp, payload, 0);
      if (msg->attr == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_FSETSTAT:
      msg->handle = buffer_get_ssh_string(payload);
      if (msg->handle == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->attr = sftp_parse_attr(sftp, payload, 0);
      if (msg->attr == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      break;
    case SSH_FXP_LSTAT:
    case SSH_FXP_STAT:
      tmp = buffer_get_ssh_string(payload);
      if (tmp == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->filename = string_to_char(tmp);
      string_free(tmp);
      if (msg->filename == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      if(sftp->version > 3) {
        buffer_get_u32(payload,&msg->flags);
      }
      break;
    case SSH_FXP_OPEN:
      tmp=buffer_get_ssh_string(payload);
      if (tmp == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      msg->filename = string_to_char(tmp);
      string_free(tmp);
      if (msg->filename == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      buffer_get_u32(payload,&msg->flags);
      msg->attr = sftp_parse_attr(sftp, payload, 0);
      if (msg->attr == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
    case SSH_FXP_FSTAT:
      msg->handle = buffer_get_ssh_string(payload);
      if (msg->handle == NULL) {
        sftp_client_message_free(msg);
        return NULL;
      }
      buffer_get_u32(payload, &msg->flags);
      break;
    default:
      fprintf(stderr, "Received unhandled sftp message %d\n", msg->type);
  }

  msg->flags = ntohl(msg->flags);
  msg->offset = ntohll(msg->offset);
  msg->len = ntohl(msg->len);
  sftp_packet_free(packet);

  return msg;
}

void sftp_client_message_free(SFTP_CLIENT_MESSAGE *msg) {
  if (msg == NULL) {
    return;
  }

  SAFE_FREE(msg->filename);
  string_free(msg->data);
  string_free(msg->handle);
  sftp_attributes_free(msg->attr);

  ZERO_STRUCTP(msg);
  SAFE_FREE(msg);
}

int sftp_reply_name(SFTP_CLIENT_MESSAGE *msg, const char *name,
    SFTP_ATTRIBUTES *attr) {
  BUFFER *out;
  STRING *file;

  out = buffer_new();
  if (out == NULL) {
    return -1;
  }

  file = string_from_char(name);
  if (file == NULL) {
    buffer_free(out);
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_u32(out, htonl(1)) < 0 ||
      buffer_add_ssh_string(out, file) < 0 ||
      buffer_add_ssh_string(out, file) < 0 || /* The protocol is broken here between 3 & 4 */
      buffer_add_attributes(out, attr) < 0 ||
      sftp_packet_write(msg->sftp, SSH_FXP_NAME, out) < 0) {
    buffer_free(out);
    string_free(file);
    return -1;
  }
  buffer_free(out);
  string_free(file);

  return 0;
}

int sftp_reply_handle(SFTP_CLIENT_MESSAGE *msg, STRING *handle){
  BUFFER *out;

  out = buffer_new();
  if (out == NULL) {
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_ssh_string(out, handle) < 0 ||
      sftp_packet_write(msg->sftp, SSH_FXP_HANDLE, out) < 0) {
    buffer_free(out);
    return -1;
  }
  buffer_free(out);

  return 0;
}

int sftp_reply_attr(SFTP_CLIENT_MESSAGE *msg, SFTP_ATTRIBUTES *attr) {
  BUFFER *out;

  out = buffer_new();
  if (out == NULL) {
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_attributes(out, attr) < 0 ||
      sftp_packet_write(msg->sftp, SSH_FXP_ATTRS, out) < 0) {
    buffer_free(out);
    return -1;
  }
  buffer_free(out);

  return 0;
}

int sftp_reply_names_add(SFTP_CLIENT_MESSAGE *msg, const char *file,
    const char *longname, SFTP_ATTRIBUTES *attr) {
  STRING *name;

  name = string_from_char(file);
  if (name == NULL) {
    return -1;
  }

  if (msg->attrbuf == NULL) {
    msg->attrbuf = buffer_new();
    if (msg->attrbuf == NULL) {
      string_free(name);
      return -1;
    }
  }

  if (buffer_add_ssh_string(msg->attrbuf, name) < 0) {
    string_free(name);
    return -1;
  }

  string_free(name);
  name = string_from_char(longname);
  if (name == NULL) {
    return -1;
  }
  if (buffer_add_ssh_string(msg->attrbuf,name) < 0 ||
      buffer_add_attributes(msg->attrbuf,attr) < 0) {
    string_free(name);
    return -1;
  }
  string_free(name);
  msg->attr_num++;

  return 0;
}

int sftp_reply_names(SFTP_CLIENT_MESSAGE *msg) {
  BUFFER *out;

  out = buffer_new();
  if (out == NULL) {
    buffer_free(msg->attrbuf);
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_u32(out, htonl(msg->attr_num)) < 0 ||
      buffer_add_data(out, buffer_get(msg->attrbuf),
        buffer_get_len(msg->attrbuf)) < 0 ||
      sftp_packet_write(msg->sftp, SSH_FXP_NAME, out) < 0) {
    buffer_free(out);
    buffer_free(msg->attrbuf);
    return -1;
  }

  buffer_free(out);
  buffer_free(msg->attrbuf);

  msg->attr_num = 0;
  msg->attrbuf = NULL;

  return 0;
}

int sftp_reply_status(SFTP_CLIENT_MESSAGE *msg, u32 status,
    const char *message) {
  BUFFER *out;
  STRING *s;

  out = buffer_new();
  if (out == NULL) {
    return -1;
  }

  s = string_from_char(message ? message : "");
  if (s == NULL) {
    buffer_free(out);
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_u32(out, htonl(status)) < 0 ||
      buffer_add_ssh_string(out, s) < 0 ||
      buffer_add_u32(out, 0) < 0 || /* language string */
      sftp_packet_write(msg->sftp, SSH_FXP_STATUS, out) < 0) {
    buffer_free(out);
    string_free(s);
    return -1;
  }

  buffer_free(out);
  string_free(s);

  return 0;
}

int sftp_reply_data(SFTP_CLIENT_MESSAGE *msg, const void *data, int len) {
  BUFFER *out;

  out = buffer_new();
  if (out == NULL) {
    return -1;
  }

  if (buffer_add_u32(out, msg->id) < 0 ||
      buffer_add_u32(out, ntohl(len)) < 0 ||
      buffer_add_data(out, data, len) < 0 ||
      sftp_packet_write(msg->sftp, SSH_FXP_DATA, out) < 0) {
    buffer_free(out);
    return -1;
  }
  buffer_free(out);

  return 0;
}

/*
 * This function will return you a new handle to give the client.
 * the function accepts an info that can be retrieved later with
 * the handle. Care is given that a corrupted handle won't give a
 * valid info (or worse).
 */
STRING *sftp_handle_alloc(SFTP_SESSION *sftp, void *info) {
  STRING *ret;
  u32 val;
  int i;

  if (sftp->handles == NULL) {
    sftp->handles = malloc(sizeof(void *) * SFTP_HANDLES);
    if (sftp->handles == NULL) {
      return NULL;
    }
    memset(sftp->handles, 0, sizeof(void *) * SFTP_HANDLES);
  }

  for (i = 0; i < SFTP_HANDLES; i++) {
    if (sftp->handles[i] == NULL) {
      break;
    }
  }

  if (i == SFTP_HANDLES) {
    return NULL; /* no handle available */
  }

  val = i;
  ret = string_new(4);
  if (ret == NULL) {
    return NULL;
  }

  memcpy(ret->string, &val, sizeof(u32));
  sftp->handles[i] = info;

  return ret;
}

void *sftp_handle(SFTP_SESSION *sftp, STRING *handle){
  u32 val;

  if (sftp->handles == NULL) {
    return NULL;
  }

  if (string_len(handle) != sizeof(u32)) {
    return NULL;
  }

  memcpy(&val, handle->string, sizeof(u32));

  if (val > SFTP_HANDLES) {
    return NULL;
  }

  return sftp->handles[val];
}

void sftp_handle_remove(SFTP_SESSION *sftp, void *handle) {
  int i;

  for (i = 0; i < SFTP_HANDLES; i++) {
    if (sftp->handles[i] == handle) {
      sftp->handles[i] = NULL;
      break;
    }
  }
}

