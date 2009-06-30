/*
 * sftp.c - Secure FTP functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
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

/* This file contains code written by Nick Zitzmann */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/sftp.h"

#ifdef WITH_SFTP

#define sftp_enter_function() _enter_function(sftp->channel->session)
#define sftp_leave_function() _leave_function(sftp->channel->session)

/* functions */
static int sftp_enqueue(SFTP_SESSION *session, SFTP_MESSAGE *msg);
static void sftp_message_free(SFTP_MESSAGE *msg);
static void sftp_set_error(SFTP_SESSION *sftp, int errnum);
static void status_msg_free(STATUS_MESSAGE *status);

SFTP_SESSION *sftp_new(SSH_SESSION *session){
  SFTP_SESSION *sftp;

  enter_function();

  if (session == NULL) {
    leave_function();
    return NULL;
  }

  sftp = malloc(sizeof(SFTP_SESSION));
  if (sftp == NULL) {
    leave_function();
    return NULL;
  }
  memset(sftp,0,sizeof(SFTP_SESSION));

  sftp->session = session;
  sftp->channel = channel_new(session);
  if (sftp->channel == NULL) {
    SAFE_FREE(sftp);
    leave_function();
    return NULL;
  }

  if (channel_open_session(sftp->channel)) {
    channel_free(sftp->channel);
    SAFE_FREE(sftp);
    leave_function();
    return NULL;
  }

  if (channel_request_sftp(sftp->channel)) {
    sftp_free(sftp);
    leave_function();
    return NULL;
  }

  leave_function();
  return sftp;
}

#ifdef WITH_SERVER
SFTP_SESSION *sftp_server_new(SSH_SESSION *session, CHANNEL *chan){
  SFTP_SESSION *sftp = NULL;

  sftp = malloc(sizeof(SFTP_SESSION));
  if (sftp == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(sftp);

  sftp->session = session;
  sftp->channel = chan;

  return sftp;
}

int sftp_server_init(SFTP_SESSION *sftp){
  struct ssh_session *session = sftp->session;
  SFTP_PACKET *packet = NULL;
  BUFFER *reply = NULL;
  u32 version;

  sftp_enter_function();

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    sftp_leave_function();
    return -1;
  }

  if (packet->type != SSH_FXP_INIT) {
    ssh_set_error(session, SSH_FATAL,
        "Packet read of type %d instead of SSH_FXP_INIT",
        packet->type);

    sftp_packet_free(packet);
    sftp_leave_function();
    return -1;
  }

  ssh_log(session, SSH_LOG_PACKET, "Received SSH_FXP_INIT");

  buffer_get_u32(packet->payload, &version);
  version = ntohl(version);
  ssh_log(session, SSH_LOG_PACKET, "Client version: %d", version);
  sftp->client_version = version;

  sftp_packet_free(packet);

  reply = buffer_new();
  if (reply == NULL) {
    sftp_leave_function();
    return -1;
  }

  if (buffer_add_u32(reply, ntohl(LIBSFTP_VERSION)) < 0) {
    buffer_free(reply);
    sftp_leave_function();
    return -1;
  }

  if (sftp_packet_write(sftp, SSH_FXP_VERSION, reply) < 0) {
    buffer_free(reply);
    sftp_leave_function();
    return -1;
  }
  buffer_free(reply);

  ssh_log(session, SSH_LOG_RARE, "Server version sent");

  if (version > LIBSFTP_VERSION) {
    sftp->version = LIBSFTP_VERSION;
  } else {
    sftp->version=version;
  }

  sftp_leave_function();
  return 0;
}
#endif /* WITH_SERVER */

void sftp_free(SFTP_SESSION *sftp){
  struct request_queue *ptr;

  if (sftp == NULL) {
    return;
  }

  channel_send_eof(sftp->channel);
  ptr = sftp->queue;
  while(ptr) {
    struct request_queue *old;
    sftp_message_free(ptr->message);
    old = ptr->next;
    SAFE_FREE(ptr);
    ptr = old;
  }

  channel_free(sftp->channel);
  memset(sftp, 0, sizeof(*sftp));

  SAFE_FREE(sftp);
}

int sftp_packet_write(SFTP_SESSION *sftp,u8 type, BUFFER *payload){
  int size;

  if (buffer_prepend_data(payload, &type, sizeof(u8)) < 0) {
    return -1;
  }

  size = htonl(buffer_get_len(payload));
  if (buffer_prepend_data(payload, &size, sizeof(u32)) < 0) {
    return -1;
  }

  size = channel_write(sftp->channel, buffer_get(payload),
      buffer_get_len(payload));
  if (size < 0) {
    return -1;
  } else if((u32) size != buffer_get_len(payload)) {
    ssh_log(sftp->session, SSH_LOG_PACKET,
        "Had to write %d bytes, wrote only %d",
        buffer_get_len(payload),
        size);
  }

  return size;
}

SFTP_PACKET *sftp_packet_read(SFTP_SESSION *sftp) {
  SFTP_PACKET *packet = NULL;
  u32 size;

  sftp_enter_function();

  packet = malloc(sizeof(SFTP_PACKET));
  if (packet == NULL) {
    return NULL;
  }
  packet->sftp = sftp;
  packet->payload = buffer_new();
  if (packet->payload == NULL) {
    SAFE_FREE(packet);
    return NULL;
  }

  if (channel_read_buffer(sftp->channel, packet->payload, 4, 0) <= 0) {
    buffer_free(packet->payload);
    SAFE_FREE(packet);
    sftp_leave_function();
    return NULL;
  }

  if (buffer_get_u32(packet->payload, &size) < 0) {
    buffer_free(packet->payload);
    SAFE_FREE(packet);
    sftp_leave_function();
    return NULL;
  }

  size = ntohl(size);
  if (channel_read_buffer(sftp->channel, packet->payload, 1, 0) <= 0) {
    buffer_free(packet->payload);
    SAFE_FREE(packet);
    sftp_leave_function();
    return NULL;
  }

  buffer_get_u8(packet->payload, &packet->type);
  if (size > 1) {
    if (channel_read_buffer(sftp->channel, packet->payload, size - 1, 0) <= 0) {
      buffer_free(packet->payload);
      SAFE_FREE(packet);
      sftp_leave_function();
      return NULL;
    }
  }

  sftp_leave_function();
  return packet;
}

static void sftp_set_error(SFTP_SESSION *sftp, int errnum) {
  if (sftp != NULL) {
    sftp->errnum = errnum;
  }
}

/* Get the last sftp error */
int sftp_get_error(SFTP_SESSION *sftp) {
  if (sftp == NULL) {
    return -1;
  }

  return sftp->errnum;
}

static SFTP_MESSAGE *sftp_message_new(SFTP_SESSION *sftp){
  SFTP_MESSAGE *msg = NULL;

  sftp_enter_function();

  msg = malloc(sizeof(SFTP_MESSAGE));
  if (msg == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(msg);

  msg->payload = buffer_new();
  if (msg->payload == NULL) {
    SAFE_FREE(msg);
    return NULL;
  }
  msg->sftp = sftp;

  sftp_leave_function();
  return msg;
}

static void sftp_message_free(SFTP_MESSAGE *msg) {
  SFTP_SESSION *sftp;

  if (msg == NULL) {
    return;
  }

  sftp = msg->sftp;
  sftp_enter_function();

  buffer_free(msg->payload);
  SAFE_FREE(msg);

  sftp_leave_function();
}

static SFTP_MESSAGE *sftp_get_message(SFTP_PACKET *packet) {
  SFTP_SESSION *sftp = packet->sftp;
  SFTP_MESSAGE *msg = NULL;

  sftp_enter_function();

  msg = sftp_message_new(sftp);
  if (msg == NULL) {
    sftp_leave_function();
    return NULL;
  }

  msg->sftp = packet->sftp;
  msg->packet_type = packet->type;

  if ((packet->type != SSH_FXP_STATUS) && (packet->type!=SSH_FXP_HANDLE) &&
      (packet->type != SSH_FXP_DATA) && (packet->type != SSH_FXP_ATTRS) &&
      (packet->type != SSH_FXP_NAME)) {
    ssh_set_error(packet->sftp->session, SSH_FATAL, 
        "Unknown packet type %d", packet->type);
    sftp_message_free(msg);
    sftp_leave_function();
    return NULL;
  }

  if (buffer_get_u32(packet->payload, &msg->id) != sizeof(u32)) {
    ssh_set_error(packet->sftp->session, SSH_FATAL,
        "Invalid packet %d: no ID", packet->type);
    sftp_message_free(msg);
    sftp_leave_function();
    return NULL;
  }

  ssh_log(packet->sftp->session, SSH_LOG_PACKET,
      "Packet with id %d type %d",
      msg->id,
      msg->packet_type);

  if (buffer_add_data(msg->payload, buffer_get_rest(packet->payload),
        buffer_get_rest_len(packet->payload)) < 0) {
    sftp_message_free(msg);
    sftp_leave_function();
    return NULL;
  }

  sftp_leave_function();
  return msg;
}

static int sftp_read_and_dispatch(SFTP_SESSION *sftp) {
  SFTP_PACKET *packet = NULL;
  SFTP_MESSAGE *msg = NULL;

  sftp_enter_function();

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    sftp_leave_function();
    return -1; /* something nasty happened reading the packet */
  }

  msg = sftp_get_message(packet);
  sftp_packet_free(packet);
  if (msg == NULL) {
    sftp_leave_function();
    return -1;
  }

  if (sftp_enqueue(sftp, msg) < 0) {
    sftp_message_free(msg);
    sftp_leave_function();
    return -1;
  }

  sftp_leave_function();
  return 0;
}

void sftp_packet_free(SFTP_PACKET *packet) {
  if (packet == NULL) {
    return;
  }

  buffer_free(packet->payload);
  free(packet);
}

/* Initialize the sftp session with the server. */
int sftp_init(SFTP_SESSION *sftp) {
  SFTP_PACKET *packet = NULL;
  BUFFER *buffer = NULL;
  STRING *ext_name_s = NULL;
  STRING *ext_data_s = NULL;
  char *ext_name = NULL;
  char *ext_data = NULL;
  u32 version = htonl(LIBSFTP_VERSION);

  sftp_enter_function();

  buffer = buffer_new();
  if (buffer == NULL) {
    sftp_leave_function();
    return -1;
  }

  if ((buffer_add_u32(buffer, version) < 0) ||
      sftp_packet_write(sftp, SSH_FXP_INIT, buffer) < 0) {
    buffer_free(buffer);
    sftp_leave_function();
    return -1;
  }
  buffer_free(buffer);

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    sftp_leave_function();
    return -1;
  }

  if (packet->type != SSH_FXP_VERSION) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received a %d messages instead of SSH_FXP_VERSION", packet->type);
    sftp_packet_free(packet);
    sftp_leave_function();
    return -1;
  }

  buffer_get_u32(packet->payload,&version);
  version = ntohl(version);

  ext_name_s = buffer_get_ssh_string(packet->payload);
  ext_data_s = buffer_get_ssh_string(packet->payload);
  if (ext_name_s == NULL || (ext_data_s == NULL)) {
    string_free(ext_name_s);
    string_free(ext_data_s);
    ssh_log(sftp->session, SSH_LOG_RARE,
        "SFTP server version %d", version);
  } else {
    ext_name = string_to_char(ext_name_s);
    ext_data = string_to_char(ext_data_s);

    if (ext_name != NULL || ext_data != NULL) {
      ssh_log(sftp->session, SSH_LOG_RARE,
          "SFTP server version %d (%s,%s)",
          version, ext_name, ext_data);
    } else {
      ssh_log(sftp->session, SSH_LOG_RARE,
          "SFTP server version %d", version);
    }
    SAFE_FREE(ext_name);
    SAFE_FREE(ext_data);
  }
  string_free(ext_name_s);
  string_free(ext_data_s);

  sftp_packet_free(packet);

  sftp->version = sftp->server_version = version;

  sftp_leave_function();
  return 0;
}

static REQUEST_QUEUE *request_queue_new(SFTP_MESSAGE *msg) {
  REQUEST_QUEUE *queue = NULL;

  queue = malloc(sizeof(REQUEST_QUEUE));
  if (queue == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(queue);

  queue->message = msg;

  return queue;
}

static void request_queue_free(REQUEST_QUEUE *queue) {
  if (queue == NULL) {
    return;
  }

  ZERO_STRUCTP(queue);
  SAFE_FREE(queue);
}

static int sftp_enqueue(SFTP_SESSION *sftp, SFTP_MESSAGE *msg) {
  REQUEST_QUEUE *queue = NULL;
  REQUEST_QUEUE *ptr;

  queue = request_queue_new(msg);
  if (queue == NULL) {
    return -1;
  }

  ssh_log(sftp->session, SSH_LOG_PACKET,
      "Queued msg type %d id %d",
      msg->id, msg->packet_type);

  if(sftp->queue == NULL) {
    sftp->queue = queue;
  } else {
    ptr = sftp->queue;
    while(ptr->next) {
      ptr=ptr->next; /* find end of linked list */
    }
    ptr->next = queue; /* add it on bottom */
  }

  return 0;
}

/*
 * Pulls of a message from the queue based on the ID.
 * Returns NULL if no message has been found.
 */
static SFTP_MESSAGE *sftp_dequeue(SFTP_SESSION *sftp, u32 id){
  REQUEST_QUEUE *prev = NULL;
  REQUEST_QUEUE *queue;
  SFTP_MESSAGE *msg;

  if(sftp->queue == NULL) {
    return NULL;
  }

  queue = sftp->queue;
  while (queue) {
    if(queue->message->id == id) {
      /* remove from queue */
      if (prev == NULL) {
        sftp->queue = queue->next;
      } else {
        prev->next = queue->next;
      }
      msg = queue->message;
      request_queue_free(queue);
      ssh_log(sftp->session, SSH_LOG_PACKET,
          "Dequeued msg id %d type %d",
          msg->id,
          msg->packet_type);
      return msg;
    }
    prev = queue;
    queue = queue->next;
  }

  return NULL;
}

/*
 * Assigns a new SFTP ID for new requests and assures there is no collision
 * between them.
 * Returns a new ID ready to use in a request
 */
static inline u32 sftp_get_new_id(SFTP_SESSION *session) {
  return ++session->id_counter;
}

static STATUS_MESSAGE *parse_status_msg(SFTP_MESSAGE *msg){
  STATUS_MESSAGE *status;

  if (msg->packet_type != SSH_FXP_STATUS) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Not a ssh_fxp_status message passed in!");
    return NULL;
  }

  status = malloc(sizeof(STATUS_MESSAGE));
  if (status == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(status);

  status->id = msg->id;
  if ((buffer_get_u32(msg->payload,&status->status) != 4) ||
      (status->error = buffer_get_ssh_string(msg->payload)) == NULL ||
      (status->lang = buffer_get_ssh_string(msg->payload)) == NULL) {
    string_free(status->error);
    /* status->lang never get allocated if something failed */
    SAFE_FREE(status);
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Invalid SSH_FXP_STATUS message");
    return NULL;
  }

  status->status = ntohl(status->status);
  status->errormsg = string_to_char(status->error);
  status->langmsg = string_to_char(status->lang);
  if (status->errormsg == NULL || status->langmsg == NULL) {
    status_msg_free(status);
    return NULL;
  }

  return status;
}

static void status_msg_free(STATUS_MESSAGE *status){
  if (status == NULL) {
    return;
  }

  string_free(status->error);
  string_free(status->lang);
  SAFE_FREE(status->errormsg);
  SAFE_FREE(status->langmsg);
  SAFE_FREE(status);
}

static SFTP_FILE *parse_handle_msg(SFTP_MESSAGE *msg){
  SFTP_FILE *file;

  if(msg->packet_type != SSH_FXP_HANDLE) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Not a ssh_fxp_handle message passed in!");
    return NULL;
  }

  file = malloc(sizeof(SFTP_FILE));
  if (file == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(file);

  file->handle = buffer_get_ssh_string(msg->payload);
  if (file->handle == NULL) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Invalid SSH_FXP_HANDLE message");
    SAFE_FREE(file);
    return NULL;
  }

  file->sftp = msg->sftp;
  file->offset = 0;
  file->eof = 0;

  return file;
}

/* Open a directory */
SFTP_DIR *sftp_opendir(SFTP_SESSION *sftp, const char *path){
  SFTP_MESSAGE *msg = NULL;
  SFTP_FILE *file = NULL;
  SFTP_DIR *dir = NULL;
  STATUS_MESSAGE *status;
  STRING *path_s;
  BUFFER *payload;
  u32 id;

  payload = buffer_new();
  if (payload == NULL) {
    return NULL;
  }

  path_s = string_from_char(path);
  if (path_s == NULL) {
    buffer_free(payload);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(payload, id) < 0 ||
      buffer_add_ssh_string(payload, path_s) < 0) {
    buffer_free(payload);
    string_free(path_s);
    return NULL;
  }
  string_free(path_s);

  if (sftp_packet_write(sftp, SSH_FXP_OPENDIR, payload) < 0) {
    buffer_free(payload);
    return NULL;
  }
  buffer_free(payload);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return NULL;
      }
      sftp_set_error(sftp, status->status);
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return NULL;
    case SSH_FXP_HANDLE:
      file = parse_handle_msg(msg);
      sftp_message_free(msg);
      if (file != NULL) {
        dir = malloc(sizeof(SFTP_DIR));
        if (dir == NULL) {
          return NULL;
        }
        ZERO_STRUCTP(dir);

        dir->sftp = sftp;
        dir->name = strdup(path);
        if (dir->name == NULL) {
          SAFE_FREE(dir);
          SAFE_FREE(file);
          return NULL;
        }
        dir->handle = file->handle;
        SAFE_FREE(file);
      }
      return dir;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during opendir!", msg->packet_type);
      sftp_message_free(msg);
  }

  return NULL;
}

/*
 * Parse the attributes from a payload from some messages. It is coded on
 * baselines from the protocol version 4.
 * This code is more or less dead but maybe we need it in future.
 */
static SFTP_ATTRIBUTES *sftp_parse_attr_4(SFTP_SESSION *sftp, BUFFER *buf,
    int expectnames) {
  SFTP_ATTRIBUTES *attr;
  STRING *owner = NULL;
  STRING *group = NULL;
  u32 flags = 0;
  int ok = 0;

  /* unused member variable */
  (void) expectnames;

  attr = malloc(sizeof(SFTP_ATTRIBUTES));
  if (attr == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(attr);

  /* This isn't really a loop, but it is like a try..catch.. */
  do {
    if (buffer_get_u32(buf, &flags) != 4) {
      break;
    }

    flags = ntohl(flags);
    attr->flags = flags;

    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      if (buffer_get_u64(buf, &attr->size) != 8) {
        break;
      }
      attr->size = ntohll(attr->size);
    }

    if (flags & SSH_FILEXFER_ATTR_OWNERGROUP) {
      if((owner = buffer_get_ssh_string(buf)) == NULL ||
        (attr->owner = string_to_char(owner)) == NULL) {
        break;
      }
      if ((group = buffer_get_ssh_string(buf)) == NULL ||
        (attr->group = string_to_char(group)) == NULL) {
        break;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      if (buffer_get_u32(buf, &attr->permissions) != 4) {
        break;
      }
      attr->permissions = ntohl(attr->permissions);

#ifndef _WIN32
      /* FIXME on windows! */
      switch (attr->permissions & S_IFMT) {
        case S_IFSOCK:
        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
          attr->type = SSH_FILEXFER_TYPE_SPECIAL;
          break;
        case S_IFLNK:
          attr->type = SSH_FILEXFER_TYPE_SYMLINK;
          break;
        case S_IFREG:
          attr->type = SSH_FILEXFER_TYPE_REGULAR;
          break;
        case S_IFDIR:
          attr->type = SSH_FILEXFER_TYPE_DIRECTORY;
          break;
        default:
          attr->type = SSH_FILEXFER_TYPE_UNKNOWN;
          break;
      }
#endif /* _WIN32 */
    }

    if (flags & SSH_FILEXFER_ATTR_ACCESSTIME) {
      if (buffer_get_u64(buf, &attr->atime64) != 8) {
        break;
      }
      attr->atime64 = ntohll(attr->atime64);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->atime_nseconds) != 4) {
        break;
      }
      attr->atime_nseconds = ntohl(attr->atime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_CREATETIME) {
      if (buffer_get_u64(buf, &attr->createtime) != 8) {
        break;
      }
      attr->createtime = ntohll(attr->createtime);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->createtime_nseconds) != 4) {
        break;
      }
      attr->createtime_nseconds = ntohl(attr->createtime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_MODIFYTIME) {
      if (buffer_get_u64(buf, &attr->mtime64) != 8) {
        break;
      }
      attr->mtime64 = ntohll(attr->mtime64);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->mtime_nseconds) != 4) {
        break;
      }
      attr->mtime_nseconds = ntohl(attr->mtime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_ACL) {
      if ((attr->acl = buffer_get_ssh_string(buf)) == NULL) {
        break;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_EXTENDED) {
      if (buffer_get_u32(buf,&attr->extended_count) != 4) {
        break;
      }
      attr->extended_count = ntohl(attr->extended_count);

      while(attr->extended_count &&
          (attr->extended_type = buffer_get_ssh_string(buf)) &&
          (attr->extended_data = buffer_get_ssh_string(buf))){
        attr->extended_count--;
      }

      if (attr->extended_count) {
        break;
      }
    }
    ok = 1;
  } while (0);

  if (ok == 0) {
    /* break issued somewhere */
    string_free(owner);
    string_free(group);
    string_free(attr->acl);
    string_free(attr->extended_type);
    string_free(attr->extended_data);
    SAFE_FREE(attr->owner);
    SAFE_FREE(attr->group);
    SAFE_FREE(attr);

    ssh_set_error(sftp->session, SSH_FATAL, "Invalid ATTR structure");

    return NULL;
  }

  return attr;
}

/* Version 3 code. it is the only one really supported (the draft for the 4 misses clarifications) */
/* maybe a paste of the draft is better than the code */
/*
        uint32   flags
        uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
        uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
        uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
        uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
        uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
        uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
        uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
        string   extended_type
        string   extended_data
        ...      more extended data (extended_type - extended_data pairs),
                   so that number of pairs equals extended_count              */
static SFTP_ATTRIBUTES *sftp_parse_attr_3(SFTP_SESSION *sftp, BUFFER *buf,
    int expectname) {
  STRING *longname = NULL;
  STRING *name = NULL;
  SFTP_ATTRIBUTES *attr;
  u32 flags = 0;
  int ok = 0;

  attr = malloc(sizeof(SFTP_ATTRIBUTES));
  if (attr == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(attr);

  /* This isn't really a loop, but it is like a try..catch.. */
  do {
    if (expectname) {
      if ((name = buffer_get_ssh_string(buf)) == NULL ||
          (attr->name = string_to_char(name)) == NULL) {
        break;
      }
      string_free(name);

      ssh_log(sftp->session, SSH_LOG_RARE, "Name: %s", attr->name);

      if ((longname=buffer_get_ssh_string(buf)) == NULL ||
          (attr->longname=string_to_char(longname)) == NULL) {
        break;
      }
      string_free(longname);
    }

    if (buffer_get_u32(buf, &flags) != sizeof(u32)) {
      break;
    }
    flags = ntohl(flags);
    attr->flags = flags;
    ssh_log(sftp->session, SSH_LOG_RARE,
        "Flags: %.8lx\n", (long unsigned int) flags);

    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      if(buffer_get_u64(buf, &attr->size) != sizeof(u64)) {
        break;
      }
      attr->size = ntohll(attr->size);
      ssh_log(sftp->session, SSH_LOG_RARE,
          "Size: %llu\n",
          (long long unsigned int) attr->size);
    }

    if (flags & SSH_FILEXFER_ATTR_UIDGID) {
      if (buffer_get_u32(buf, &attr->uid) != sizeof(u32)) {
        break;
      }
      if (buffer_get_u32(buf, &attr->gid) != sizeof(u32)) {
        break;
      }
      attr->uid = ntohl(attr->uid);
      attr->gid = ntohl(attr->gid);
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      if (buffer_get_u32(buf, &attr->permissions) != sizeof(u32)) {
        break;
      }
      attr->permissions = ntohl(attr->permissions);

#ifndef _WIN32
      /* FIXME on windows */
      switch (attr->permissions & S_IFMT) {
        case S_IFSOCK:
        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
          attr->type = SSH_FILEXFER_TYPE_SPECIAL;
          break;
        case S_IFLNK:
          attr->type = SSH_FILEXFER_TYPE_SYMLINK;
          break;
        case S_IFREG:
          attr->type = SSH_FILEXFER_TYPE_REGULAR;
          break;
        case S_IFDIR:
          attr->type = SSH_FILEXFER_TYPE_DIRECTORY;
          break;
        default:
          attr->type = SSH_FILEXFER_TYPE_UNKNOWN;
          break;
      }
#endif /* _WIN32 */
    }

    if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
      if (buffer_get_u32(buf, &attr->atime) != sizeof(u32)) {
        break;
      }
      attr->atime = ntohl(attr->atime);
      if (buffer_get_u32(buf, &attr->mtime) != sizeof(u32)) {
        break;
      }
      attr->mtime = ntohl(attr->mtime);
    }

    if (flags & SSH_FILEXFER_ATTR_EXTENDED) {
      if (buffer_get_u32(buf, &attr->extended_count) != sizeof(u32)) {
        break;
      }

      attr->extended_count = ntohl(attr->extended_count);
      while (attr->extended_count &&
          (attr->extended_type = buffer_get_ssh_string(buf))
          && (attr->extended_data = buffer_get_ssh_string(buf))) {
        attr->extended_count--;
      }

      if (attr->extended_count) {
        break;
      }
    }
    ok = 1;
  } while (0);

  if (!ok) {
    /* break issued somewhere */
    string_free(name);
    string_free(longname);
    string_free(attr->extended_type);
    string_free(attr->extended_data);
    SAFE_FREE(attr->name);
    SAFE_FREE(attr->longname);
    SAFE_FREE(attr);

    ssh_set_error(sftp->session, SSH_FATAL, "Invalid ATTR structure");

    return NULL;
  }

  /* everything went smoothly */
  return attr;
}

/* FIXME is this really needed as a public function? */
int buffer_add_attributes(BUFFER *buffer, SFTP_ATTRIBUTES *attr) {
  u32 flags = (attr ? attr->flags : 0);

  flags &= (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
      SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);

  if (buffer_add_u32(buffer, htonl(flags)) < 0) {
    return -1;
  }

  if (attr) {
    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      if (buffer_add_u64(buffer, htonll(attr->size)) < 0) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_UIDGID) {
      if (buffer_add_u32(buffer,htonl(attr->uid)) < 0 ||
          buffer_add_u32(buffer,htonl(attr->gid)) < 0) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      if (buffer_add_u32(buffer, htonl(attr->permissions)) < 0) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
      if (buffer_add_u32(buffer, htonl(attr->atime)) < 0 ||
          buffer_add_u32(buffer, htonl(attr->mtime)) < 0) {
        return -1;
      }
    }
  }

  return 0;
}


SFTP_ATTRIBUTES *sftp_parse_attr(SFTP_SESSION *session, BUFFER *buf,
    int expectname) {
  switch(session->version) {
    case 4:
      return sftp_parse_attr_4(session, buf, expectname);
    case 3:
      return sftp_parse_attr_3(session, buf, expectname);
    default:
      ssh_set_error(session->session, SSH_FATAL,
          "Version %d unsupported by client", session->server_version);
      return NULL;
  }

  return NULL;
}

/* Get the version of the SFTP protocol supported by the server */
int sftp_server_version(SFTP_SESSION *sftp) {
  return sftp->server_version;
}

/* Get a single file attributes structure of a directory. */
SFTP_ATTRIBUTES *sftp_readdir(SFTP_SESSION *sftp, SFTP_DIR *dir) {
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status;
  SFTP_ATTRIBUTES *attr;
  BUFFER *payload;
  u32 id;

  if (dir->buffer == NULL) {
    payload = buffer_new();
    if (payload == NULL) {
      return NULL;
    }

    id = sftp_get_new_id(sftp);
    if (buffer_add_u32(payload, id) < 0 ||
        buffer_add_ssh_string(payload, dir->handle) < 0) {
      buffer_free(payload);
      return NULL;
    }

    if (sftp_packet_write(sftp, SSH_FXP_READDIR, payload) < 0) {
      buffer_free(payload);
      return NULL;
    }
    buffer_free(payload);

    ssh_log(sftp->session, SSH_LOG_PACKET,
        "Sent a ssh_fxp_readdir with id %d", id);

    while (msg == NULL) {
      if (sftp_read_and_dispatch(sftp) < 0) {
        /* something nasty has happened */
        return NULL;
      }
      msg = sftp_dequeue(sftp, id);
    }

    switch (msg->packet_type){
      case SSH_FXP_STATUS:
        status = parse_status_msg(msg);
        sftp_message_free(msg);
        if (status == NULL) {
          return NULL;
        }
        sftp_set_error(sftp, status->status);
        switch (status->status) {
          case SSH_FX_EOF:
            dir->eof = 1;
            status_msg_free(status);
            return NULL;
          default:
            break;
        }

        ssh_set_error(sftp->session, SSH_FATAL,
            "Unknown error status: %d", status->status);
        status_msg_free(status);

        return NULL;
      case SSH_FXP_NAME:
        buffer_get_u32(msg->payload, &dir->count);
        dir->count = ntohl(dir->count);
        dir->buffer = msg->payload;
        msg->payload = NULL;
        sftp_message_free(msg);
        break;
      default:
        ssh_set_error(sftp->session, SSH_FATAL,
            "Unsupported message back %d", msg->packet_type);
        sftp_message_free(msg);

        return NULL;
    }
  }

  /* now dir->buffer contains a buffer and dir->count != 0 */
  if (dir->count == 0) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Count of files sent by the server is zero, which is invalid, or "
        "libsftp bug");
    return NULL;
  }

  ssh_log(sftp->session, SSH_LOG_RARE, "Count is %d", dir->count);

  attr = sftp_parse_attr(sftp, dir->buffer, 1);
  if (attr == NULL) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Couldn't parse the SFTP attributes");
    return NULL;
  }

  dir->count--;
  if (dir->count == 0) {
    buffer_free(dir->buffer);
    dir->buffer = NULL;
  }

  return attr;
}

/* Tell if the directory has reached EOF (End Of File). */
int sftp_dir_eof(SFTP_DIR *dir) {
  return dir->eof;
}

/* Free a SFTP_ATTRIBUTE handle */
void sftp_attributes_free(SFTP_ATTRIBUTES *file){
  if (file == NULL) {
    return;
  }

  string_free(file->acl);
  string_free(file->extended_data);
  string_free(file->extended_type);

  SAFE_FREE(file->name);
  SAFE_FREE(file->longname);
  SAFE_FREE(file->group);
  SAFE_FREE(file->owner);

  SAFE_FREE(file);
}

static int sftp_handle_close(SFTP_SESSION *sftp, STRING *handle) {
  STATUS_MESSAGE *status;
  SFTP_MESSAGE *msg = NULL;
  BUFFER *buffer = NULL;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, handle) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_CLOSE ,buffer) < 0) {
    buffer_free(buffer);
    return -1;
  }
  buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(sftp,id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if(status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_OK:
          status_msg_free(status);
          return 0;
          break;
        default:
          break;
      }
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return -1;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during sftp_handle_close!", msg->packet_type);
      sftp_message_free(msg);
  }

  return -1;
}

int sftp_file_close(SFTP_FILE *file) {
  return sftp_close(file);
}

/* Close an open file handle. */
int sftp_close(SFTP_FILE *file){
  int err = SSH_NO_ERROR;

  SAFE_FREE(file->name);
  if (file->handle){
    err = sftp_handle_close(file->sftp,file->handle);
    string_free(file->handle);
  }
  /* FIXME: check server response and implement errno */
  SAFE_FREE(file);

  return err;
}

int sftp_dir_close(SFTP_DIR *dir) {
  return sftp_closedir(dir);
}

/* Close an open directory. */
int sftp_closedir(SFTP_DIR *dir){
  int err = SSH_NO_ERROR;

  SAFE_FREE(dir->name);
  if (dir->handle) {
    err = sftp_handle_close(dir->sftp, dir->handle);
    string_free(dir->handle);
  }
  /* FIXME: check server response and implement errno */
  buffer_free(dir->buffer);
  SAFE_FREE(dir);

  return err;
}

/* Open a file on the server. */
SFTP_FILE *sftp_open(SFTP_SESSION *sftp, const char *file, int flags,
    mode_t mode) {
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status;
  SFTP_ATTRIBUTES attr;
  SFTP_FILE *handle;
  STRING *filename;
  BUFFER *buffer;
  u32 sftp_flags = 0;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return NULL;
  }

  filename = string_from_char(file);
  if (filename == NULL) {
    buffer_free(buffer);
    return NULL;
  }

  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  if (flags == O_RDONLY)
    sftp_flags |= SSH_FXF_READ; /* if any of the other flag is set,
                                   READ should not be set initialy */
  if (flags & O_WRONLY)
    sftp_flags |= SSH_FXF_WRITE;
  if (flags & O_RDWR)
    sftp_flags |= (SSH_FXF_WRITE | SSH_FXF_READ);
  if (flags & O_CREAT)
    sftp_flags |= SSH_FXF_CREAT;
  if (flags & O_TRUNC)
    sftp_flags |= SSH_FXF_TRUNC;
  if (flags & O_EXCL)
    sftp_flags |= SSH_FXF_EXCL;

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, filename) < 0) {
    buffer_free(buffer);
    string_free(filename);
    return NULL;
  }
  string_free(filename);

  if (buffer_add_u32(buffer, htonl(sftp_flags)) < 0 ||
      buffer_add_attributes(buffer, &attr) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_OPEN, buffer) < 0) {
    buffer_free(buffer);
    return NULL;
  }
  buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return NULL;
      }
      sftp_set_error(sftp, status->status);
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);

      return NULL;
    case SSH_FXP_HANDLE:
      handle = parse_handle_msg(msg);
      sftp_message_free(msg);
      return handle;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during open!", msg->packet_type);
      sftp_message_free(msg);
  }

  return NULL;
}

void sftp_file_set_nonblocking(SFTP_FILE *handle){
    handle->nonblocking=1;
}
void sftp_file_set_blocking(SFTP_FILE *handle){
    handle->nonblocking=0;
}

/* Read from a file using an opened sftp file handle. */
ssize_t sftp_read(SFTP_FILE *handle, void *buf, size_t count) {
  SFTP_SESSION *sftp = handle->sftp;
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status;
  STRING *datastring;
  BUFFER *buffer;
  int id;

  if (handle->eof) {
    return 0;
  }

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }
  id = sftp_get_new_id(handle->sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, handle->handle) < 0 ||
      buffer_add_u64(buffer, htonll(handle->offset)) < 0 ||
      buffer_add_u32(buffer,htonl(count)) < 0 ||
      sftp_packet_write(handle->sftp, SSH_FXP_READ, buffer) < 0) {
    buffer_free(buffer);
    return -1;
  }
  buffer_free(buffer);

  while (msg == NULL) {
    if (handle->nonblocking) {
      if (channel_poll(handle->sftp->channel, 0) == 0) {
        /* we cannot block */
        return 0;
      }
    }
    if (sftp_read_and_dispatch(handle->sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(handle->sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_EOF:
          handle->eof = 1;
          status_msg_free(status);
          return 0;
        default:
          break;
      }
      ssh_set_error(sftp->session,SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return -1;
    case SSH_FXP_DATA:
      datastring = buffer_get_ssh_string(msg->payload);
      sftp_message_free(msg);
      if (datastring == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received invalid DATA packet from sftp server");
        return -1;
      }

      if (string_len(datastring) > count) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received a too big DATA packet from sftp server: "
            "%zu and asked for %zu",
            string_len(datastring), count);
        string_free(datastring);
        return -1;
      }
      count = string_len(datastring);
      handle->offset += count;
      memcpy(buf, datastring->string, count);
      string_free(datastring);
      return count;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during read!", msg->packet_type);
      sftp_message_free(msg);
      return -1;
  }

  return -1; /* not reached */
}

/* Start an asynchronous read from a file using an opened sftp file handle. */
int sftp_async_read_begin(SFTP_FILE *file, u32 len){
  SFTP_SESSION *sftp = file->sftp;
  BUFFER *buffer;
  u32 id;

  sftp_enter_function();

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, file->handle) < 0 ||
      buffer_add_u64(buffer, htonll(file->offset)) < 0 ||
      buffer_add_u32(buffer, htonl(len)) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_READ, buffer) < 0) {
    buffer_free(buffer);
    return -1;
  }
  buffer_free(buffer);

  file->offset += len; /* assume we'll read len bytes */

  sftp_leave_function();
  return id;
}

/* Wait for an asynchronous read to complete and save the data. */
int sftp_async_read(SFTP_FILE *file, void *data, u32 size, u32 id){
  SFTP_SESSION *sftp = file->sftp;
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status;
  STRING *datastring;
  int err = SSH_OK;
  u32 len;

  sftp_enter_function();

  if (file->eof) {
    sftp_leave_function();
    return 0;
  }

  /* handle an existing request */
  while (msg == NULL) {
    if (file->nonblocking){
      if (channel_poll(sftp->channel, 0) == 0) {
        /* we cannot block */
        return SSH_AGAIN;
      }
    }

    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      sftp_leave_function();
      return SSH_ERROR;
    }

    msg = sftp_dequeue(sftp,id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        sftp_leave_function();
        return -1;
      }
      sftp_set_error(sftp, status->status);
      if (status->status != SSH_FX_EOF) {
        ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
            "SFTP server : %s", status->errormsg);
        sftp_leave_function();
        err = SSH_ERROR;
      } else {
        file->eof = 1;
      }
      status_msg_free(status);
      sftp_leave_function();
      return err;
    case SSH_FXP_DATA:
      datastring = buffer_get_ssh_string(msg->payload);
      sftp_message_free(msg);
      if (datastring == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received invalid DATA packet from sftp server");
        sftp_leave_function();
        return SSH_ERROR;
      }
      if (string_len(datastring) > size) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received a too big DATA packet from sftp server: "
            "%zu and asked for %u",
            string_len(datastring), size);
        string_free(datastring);
        sftp_leave_function();
        return SSH_ERROR;
      }
      len = string_len(datastring);
      //handle->offset+=len;
      /* We already have set the offset previously. All we can do is warn that the expected len
       * and effective lengths are different */
      memcpy(data, datastring->string, len);
      string_free(datastring);
      sftp_leave_function();
      return len;
    default:
      ssh_set_error(sftp->session,SSH_FATAL,"Received message %d during read!",msg->packet_type);
      sftp_message_free(msg);
      sftp_leave_function();
      return SSH_ERROR;
  }

  sftp_leave_function();
  return SSH_ERROR;
}

ssize_t sftp_write(SFTP_FILE *file, const void *buf, size_t count) {
  SFTP_SESSION *sftp = file->sftp;
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status;
  STRING *datastring;
  BUFFER *buffer;
  u32 id;
  int len;
  int packetlen;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  datastring = string_new(count);
  if (datastring == NULL) {
    buffer_free(buffer);
    return -1;
  }
  string_fill(datastring, buf, count);

  id = sftp_get_new_id(file->sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, file->handle) < 0 ||
      buffer_add_u64(buffer, htonll(file->offset)) < 0 ||
      buffer_add_ssh_string(buffer, datastring) < 0) {
    buffer_free(buffer);
    string_free(datastring);
    return -1;
  }
  string_free(datastring);
  len = sftp_packet_write(file->sftp, SSH_FXP_WRITE, buffer);
  packetlen=buffer_get_len(buffer);
  buffer_free(buffer);
  if (len < 0) {
    return -1;
  } else  if (len != packetlen) {
    ssh_log(sftp->session, SSH_LOG_PACKET,
        "Could not write as much data as expected");
  }

  while (msg == NULL) {
    if (sftp_read_and_dispatch(file->sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(file->sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_OK:
          file->offset += count;
          status_msg_free(status);
          return count;
        default:
          break;
      }
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      file->offset += count;
      status_msg_free(status);
      return -1;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during write!", msg->packet_type);
      sftp_message_free(msg);
      return -1;
  }

  return -1; /* not reached */
}

/* Seek to a specific location in a file. */
int sftp_seek(SFTP_FILE *file, u32 new_offset) {
  if (file == NULL) {
    return -1;
  }

  file->offset = new_offset;

  return 0;
}

int sftp_seek64(SFTP_FILE *file, u64 new_offset) {
  if (file == NULL) {
    return -1;
  }

  file->offset = new_offset;

  return 0;
}

/* Report current byte position in file. */
unsigned long sftp_tell(SFTP_FILE *file) {
  return file->offset;
}

/* Rewinds the position of the file pointer to the beginning of the file.*/
void sftp_rewind(SFTP_FILE *file) {
  file->offset = 0;
}

/* deprecated */
int sftp_rm(SFTP_SESSION *sftp, const char *file) {
  return sftp_unlink(sftp, file);
}

/* code written by Nick */
int sftp_unlink(SFTP_SESSION *sftp, const char *file) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  STRING *filename;
  BUFFER *buffer;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  filename = string_from_char(file);
  if (filename == NULL) {
    buffer_free(buffer);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, filename) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_REMOVE, buffer) < 0) {
    buffer_free(buffer);
    string_free(filename);
  }
  string_free(filename);
  buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp)) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_STATUS) {
    /* by specification, this command's only supposed to return SSH_FXP_STATUS */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }

    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session,SSH_FATAL,
        "Received message %d when attempting to remove file", msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* code written by Nick */
int sftp_rmdir(SFTP_SESSION *sftp, const char *directory) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  STRING *filename;
  BUFFER *buffer;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  filename = string_from_char(directory);
  if (filename == NULL) {
    buffer_free(buffer);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, filename) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_RMDIR, buffer) < 0) {
    buffer_free(buffer);
    string_free(filename);
    return -1;
  }
  buffer_free(buffer);
  string_free(filename);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
        break;
      default:
        break;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to remove directory",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Code written by Nick */
int sftp_mkdir(SFTP_SESSION *sftp, const char *directory, mode_t mode) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  SFTP_ATTRIBUTES *errno_attr = NULL;
  SFTP_ATTRIBUTES attr;
  BUFFER *buffer;
  STRING *path;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  path = string_from_char(directory);
  if (path == NULL) {
    buffer_free(buffer);
    return -1;
  }

  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, path) < 0 ||
      buffer_add_attributes(buffer, &attr) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_MKDIR, buffer) < 0) {
    buffer_free(buffer);
    string_free(path);
  }
  buffer_free(buffer);
  string_free(path);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_FAILURE:
        /*
         * mkdir always returns a failure, even if the path already exists.
         * To be POSIX conform and to be able to map it to EEXIST a stat
         * call is needed here.
         */
        errno_attr = sftp_lstat(sftp, directory);
        if (errno_attr != NULL) {
          SAFE_FREE(errno_attr);
          sftp_set_error(sftp, SSH_FX_FILE_ALREADY_EXISTS);
        }
        break;
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
        break;
      default:
        break;
    }
    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to make directory",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* code written by nick */
int sftp_rename(SFTP_SESSION *sftp, const char *original, const char *newname) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  BUFFER *buffer;
  STRING *oldpath;
  STRING *newpath;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  oldpath = string_from_char(original);
  if (oldpath == NULL) {
    buffer_free(buffer);
    return -1;
  }

  newpath = string_from_char(newname);
  if (newpath == NULL) {
    buffer_free(buffer);
    string_free(oldpath);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, oldpath) < 0 ||
      buffer_add_ssh_string(buffer, newpath) < 0 ||
      /* POSIX rename atomically replaces newpath, we should do the same */
      buffer_add_u32(buffer, SSH_FXF_RENAME_OVERWRITE) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_RENAME, buffer) < 0) {
    buffer_free(buffer);
    string_free(oldpath);
    string_free(newpath);
    return -1;
  }
  buffer_free(buffer);
  string_free(oldpath);
  string_free(newpath);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }
    /*
     * Status should be SSH_FX_OK if the command was successful, if it didn't,
     * then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to rename",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Code written by Nick */
/* Set file attributes on a file, directory or symbolic link. */
int sftp_setstat(SFTP_SESSION *sftp, const char *file, SFTP_ATTRIBUTES *attr) {
  u32 id = sftp_get_new_id(sftp);
  BUFFER *buffer = buffer_new();
  STRING *path = string_from_char(file);
  SFTP_MESSAGE *msg = NULL;
  STATUS_MESSAGE *status = NULL;

  buffer = buffer_new();
  if (buffer == NULL) {
    return -1;
  }

  path = string_from_char(file);
  if (path == NULL) {
    buffer_free(buffer);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, path) < 0 ||
      buffer_add_attributes(buffer, attr) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_SETSTAT, buffer) < 0) {
    buffer_free(buffer);
    string_free(path);
    return -1;
  }
  buffer_free(buffer);
  string_free(path);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }
    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Change the file owner and group */
int sftp_chown(SFTP_SESSION *sftp, const char *file, uid_t owner, gid_t group) {
  SFTP_ATTRIBUTES attr;

  ZERO_STRUCT(attr);

  attr.uid = owner;
  attr.gid = group;
  attr.flags = SSH_FILEXFER_ATTR_OWNERGROUP;

  return sftp_setstat(sftp, file, &attr);
}

/* Change permissions of a file */
int sftp_chmod(SFTP_SESSION *sftp, const char *file, mode_t mode) {
  SFTP_ATTRIBUTES attr;

  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  return sftp_setstat(sftp, file, &attr);
}

/* Change the last modification and access time of a file. */
int sftp_utimes(SFTP_SESSION *sftp, const char *file,
    const struct timeval *times) {
  SFTP_ATTRIBUTES attr;

  ZERO_STRUCT(attr);

  attr.atime = times[0].tv_sec;
  attr.atime_nseconds = times[0].tv_usec;

  attr.mtime = times[1].tv_sec;
  attr.mtime_nseconds = times[1].tv_usec;

  attr.flags |= SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_MODIFYTIME |
    SSH_FILEXFER_ATTR_SUBSECOND_TIMES;

  return sftp_setstat(sftp, file, &attr);
}

/* another code written by Nick */
char *sftp_canonicalize_path(SFTP_SESSION *sftp, const char *path) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  STRING *name = NULL;
  STRING *pathstr;
  BUFFER *buffer;
  char *cname;
  u32 ignored;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return NULL;
  }

  pathstr = string_from_char(path);
  if (pathstr == NULL) {
    buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, pathstr) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_REALPATH, buffer) < 0) {
    buffer_free(buffer);
    string_free(pathstr);
    return NULL;
  }
  buffer_free(buffer);
  string_free(pathstr);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_NAME) {
    /* we don't care about "count" */
    buffer_get_u32(msg->payload, &ignored);
    /* we only care about the file name string */
    name = buffer_get_ssh_string(msg->payload);
    sftp_message_free(msg);
    if (name == NULL) {
      return NULL;
    }
    cname = string_to_char(name);
    string_free(name);

    return cname;
  } else if (msg->packet_type == SSH_FXP_STATUS) { /* bad response (error) */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
  } else { /* this shouldn't happen */
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return NULL;
}

static SFTP_ATTRIBUTES *sftp_xstat(SFTP_SESSION *sftp, const char *path,
    int param) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  STRING *pathstr;
  BUFFER *buffer;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return NULL;
  }

  pathstr = string_from_char(path);
  if (pathstr == NULL) {
    buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, pathstr) < 0 ||
      sftp_packet_write(sftp, param, buffer) < 0) {
    buffer_free(buffer);
    string_free(pathstr);
    return NULL;
  }
  buffer_free(buffer);
  string_free(pathstr);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_ATTRS) {
    return sftp_parse_attr(sftp, msg->payload, 0);
  } else if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    sftp_set_error(sftp, status->status);
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return NULL;
  }
  ssh_set_error(sftp->session, SSH_FATAL,
      "Received mesg %d during stat()", msg->packet_type);
  sftp_message_free(msg);

  return NULL;
}

SFTP_ATTRIBUTES *sftp_stat(SFTP_SESSION *session, const char *path) {
  return sftp_xstat(session, path, SSH_FXP_STAT);
}

SFTP_ATTRIBUTES *sftp_lstat(SFTP_SESSION *session, const char *path) {
  return sftp_xstat(session, path, SSH_FXP_LSTAT);
}

SFTP_ATTRIBUTES *sftp_fstat(SFTP_FILE *file) {
  STATUS_MESSAGE *status = NULL;
  SFTP_MESSAGE *msg = NULL;
  BUFFER *buffer;
  u32 id;

  buffer = buffer_new();
  if (buffer == NULL) {
    return NULL;
  }

  id = sftp_get_new_id(file->sftp);
  if (buffer_add_u32(buffer, id) < 0 ||
      buffer_add_ssh_string(buffer, file->handle) < 0 ||
      sftp_packet_write(file->sftp, SSH_FXP_FSTAT, buffer) < 0) {
    buffer_free(buffer);
    return NULL;
  }
  buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(file->sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(file->sftp, id);
  }

  if (msg->packet_type == SSH_FXP_ATTRS){
    return sftp_parse_attr(file->sftp, msg->payload, 0);
  } else if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(file->sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);

    return NULL;
  }
  ssh_set_error(file->sftp->session, SSH_FATAL,
      "Received msg %d during fstat()", msg->packet_type);
  sftp_message_free(msg);

  return NULL;
}

#endif /* WITH_SFTP */
/* vim: set ts=2 sw=2 et cindent: */
