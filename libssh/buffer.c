/*
 * buffer.c - buffer functions
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

#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"

/** \defgroup ssh_buffer SSH Buffers
 * \brief buffer handling
 */

/** \addtogroup ssh_buffer
 * @{
 */

/** \brief creates a new buffer
 * \return a new initialized buffer, NULL on error.
 */
struct buffer_struct *buffer_new(void) {
  struct buffer_struct *buf = malloc(sizeof(struct buffer_struct));

  if (buf == NULL) {
    return NULL;
  }
  memset(buf, 0, sizeof(struct buffer_struct));

  return buf;
}

/** \brief deallocate a buffer
 * \param buffer buffer to free
 */
void buffer_free(struct buffer_struct *buffer) {
  if (buffer == NULL) {
    return;
  }

  if (buffer->data) {
    /* burn the data */
    memset(buffer->data, 0, buffer->allocated);
    SAFE_FREE(buffer->data);
  }
  memset(buffer, 'X', sizeof(*buffer));
  SAFE_FREE(buffer);
}

static int realloc_buffer(struct buffer_struct *buffer, int needed) {
  int smallest = 1;
  char *new = NULL;
  /* Find the smallest power of two which is greater or equal to needed */
  while(smallest <= needed) {
    smallest <<= 1;
  }
  needed = smallest;
  new = realloc(buffer->data, needed);
  if (new == NULL) {
    return -1;
  }
  buffer->data = new;
  buffer->allocated = needed;

  return 0;
}

/* \internal
 * \brief reinitialize a buffer
 * \param buffer buffer
 * \return 0 on sucess, < 0 on error
 */
int buffer_reinit(struct buffer_struct *buffer) {
  memset(buffer->data, 0, buffer->used);
  buffer->used = 0;
  buffer->pos = 0;
  if(buffer->allocated > 127) {
    if (realloc_buffer(buffer, 127) < 0) {
      return -1;
    }
  }
  return 0;
}

/** \internal
 * \brief add data at tail of the buffer
 * \param buffer buffer
 * \param data data pointer
 * \param len length of data
 */
int buffer_add_data(struct buffer_struct *buffer, const void *data, u32 len) {
  if (buffer->allocated < (buffer->used + len)) {
    if (realloc_buffer(buffer, buffer->used + len) < 0) {
      return -1;
    }
  }

  memcpy(buffer->data+buffer->used, data, len);
  buffer->used+=len;
  return 0;
}

/** \internal
 * \brief add a SSH string to the tail of buffer
 * \param buffer buffer
 * \param string SSH String to add
 * \return 0 on success, -1 on error.
 */
int buffer_add_ssh_string(struct buffer_struct *buffer,
    struct string_struct *string) {
  u32 len = 0;

  len = ntohl(string->size);
  if (buffer_add_data(buffer, string, len + sizeof(u32)) < 0) {
    return -1;
  }

  return 0;
}
/** \internal
 * \brief add a 32 bits unsigned integer to the tail of buffer
 * \param buffer buffer
 * \param data 32 bits integer
 * \return 0 on success, -1 on error.
 */
int buffer_add_u32(struct buffer_struct *buffer,u32 data){
  if (buffer_add_data(buffer, &data, sizeof(data)) < 0) {
    return -1;
  }

  return 0;
}

/** \internal
 * \brief add a 64 bits unsigned integer to the tail of buffer
 * \param buffer buffer
 * \param data 64 bits integer
 * \return 0 on success, -1 on error.
 */
int buffer_add_u64(struct buffer_struct *buffer, u64 data){
  if (buffer_add_data(buffer, &data, sizeof(data)) < 0) {
    return -1;
  }

  return 0;
}
/** \internal
 * \brief add a 8 bits unsigned integer to the tail of buffer
 * \param buffer buffer
 * \param data 8 bits integer
 * \return 0 on success, -1 on error.
 */
int buffer_add_u8(struct buffer_struct *buffer,u8 data){
  if (buffer_add_data(buffer, &data, sizeof(u8)) < 0) {
    return -1;
  }

  return 0;
}

/** \internal
 * \brief add data at head of a buffer
 * \param buffer buffer
 * \param data data to add
 * \param len length of data
 * \return 0 on success, -1 on error.
 */
int buffer_prepend_data(struct buffer_struct *buffer, const void *data,
    u32 len) {
  if (buffer->allocated < (buffer->used + len)) {
    if (realloc_buffer(buffer, buffer->used + len) < 0) {
      return -1;
    }
  }
  memmove(buffer->data + len, buffer->data, buffer->used);
  memcpy(buffer->data, data, len);
  buffer->used += len;

  return 0;
}

/** \internal
 * \brief append data from a buffer to tail of another
 * \param buffer destination buffer
 * \param source source buffer. Doesn't take position in buffer into account
 * \return 0 on success, -1 on error.
 */
int buffer_add_buffer(struct buffer_struct *buffer,
    struct buffer_struct *source) {
  if (buffer_add_data(buffer, buffer_get(source), buffer_get_len(source)) < 0) {
    return -1;
  }

  return 0;
}

/** \brief get a pointer on the head of the buffer
 * \param buffer buffer
 * \return data pointer on the head. Doesn't take position into account.
 * \warning don't expect data to be nul-terminated
 * \see buffer_get_rest()
 * \see buffer_get_len()
 */
void *buffer_get(struct buffer_struct *buffer){
  return buffer->data;
}

/** \internal
 * \brief get a pointer to head of the buffer at current position
 * \param buffer buffer
 * \return pointer to the data from current position
 * \see buffer_get_rest_len()
 * \see buffer_get()
 */
void *buffer_get_rest(struct buffer_struct *buffer){
    return buffer->data + buffer->pos;
}

/** \brief get length of the buffer, not counting position
 * \param buffer
 * \return length of the buffer
 * \see buffer_get()
 */
u32 buffer_get_len(struct buffer_struct *buffer){
    return buffer->used;
}

/** \internal
 *  \brief get length of the buffer from the current position
 * \param buffer
 * \return length of the buffer
 * \see buffer_get_rest()
 */
u32 buffer_get_rest_len(struct buffer_struct *buffer){
    return buffer->used - buffer->pos;
}

/** \internal
 * has effect to "eat" bytes at head of the buffer
 * \brief advance the position in the buffer
 * \param buffer buffer
 * \param len number of bytes to eat
 * \return new size of the buffer
 */
u32 buffer_pass_bytes(struct buffer_struct *buffer, u32 len){
    if(buffer->used < buffer->pos+len)
        return 0;
    buffer->pos+=len;
    /* if the buffer is empty after having passed the whole bytes into it, we can clean it */
    if(buffer->pos==buffer->used){
        buffer->pos=0;
        buffer->used=0;
    }
    return len;
}

/** \internal
 * \brief cut the end of the buffer
 * \param buffer buffer
 * \param len number of bytes to remove from tail
 * \return new size of the buffer
 */
u32 buffer_pass_bytes_end(struct buffer_struct *buffer, u32 len){
    if(buffer->used < buffer->pos + len)
        return 0;
    buffer->used-=len;
    return len;
}

/** \internal
 * \brief gets remaining data out of the buffer. Adjust the read pointer.
 * \param buffer Buffer to read
 * \param data data buffer where to store the data
 * \param len length to read from the buffer
 * \returns 0 if there is not enough data in buffer
 * \returns len otherwise.
 */
u32 buffer_get_data(struct buffer_struct *buffer, void *data, u32 len){
    /*
     * Check for a integer overflow first, then check if not enough data is in
     * the buffer.
     */
    if (buffer->pos + len < len || buffer->pos + len > buffer->used) {
      return 0;
    }
    memcpy(data,buffer->data+buffer->pos,len);
    buffer->pos+=len;
    return len;   /* no yet support for partial reads (is it really needed ?? ) */
}
/** \internal
 * \brief gets a 8 bits unsigned int out of the buffer. Adjusts the read pointer.
 * \param buffer Buffer to read
 * \param data pointer to a u8 where to store the data
 * \returns 0 if there is not enough data in buffer
 * \returns 1 otherwise.
 */
int buffer_get_u8(struct buffer_struct *buffer, u8 *data){
    return buffer_get_data(buffer,data,sizeof(u8));
}

/** \internal
 * \brief gets a 32 bits unsigned int out of the buffer. Adjusts the read pointer.
 * \param buffer Buffer to read
 * \param data pointer to a u32 where to store the data
 * \returns 0 if there is not enough data in buffer
 * \returns 4 otherwise.
 */
int buffer_get_u32(struct buffer_struct *buffer, u32 *data){
    return buffer_get_data(buffer,data,sizeof(u32));
}
/** \internal
 * \brief gets a 64 bits unsigned int out of the buffer. Adjusts the read pointer.
 * \param buffer Buffer to read
 * \param data pointer to a u64 where to store the data
 * \returns 0 if there is not enough data in buffer
 * \returns 8 otherwise.
 */
int buffer_get_u64(struct buffer_struct *buffer, u64 *data){
    return buffer_get_data(buffer,data,sizeof(u64));
}
/** \internal
 * \brief gets a SSH String out of the buffer. Adjusts the read pointer.
 * \param buffer Buffer to read
 * \returns The SSH String read
 * \returns NULL otherwise.
 */
struct string_struct *buffer_get_ssh_string(struct buffer_struct *buffer) {
  u32 stringlen;
  u32 hostlen;
  struct string_struct *str = NULL;

  if (buffer_get_u32(buffer, &stringlen) == 0) {
    return NULL;
  }
  hostlen = ntohl(stringlen);
  /* verify if there is enough space in buffer to get it */
  if ((buffer->pos + hostlen) > buffer->used) {
    return NULL; /* it is indeed */
  }
  str = string_new(hostlen);
  if (str == NULL) {
    return NULL;
  }
  if (buffer_get_data(buffer, str->string, hostlen) != hostlen) {
    /* should never happen */
    SAFE_FREE(str);
    return NULL;
  }

  return str;
}
/** \internal
 * \brief gets a mpint out of the buffer. Adjusts the read pointer.
 * SSH-1 only
 * \param buffer Buffer to read
 * \returns the SSH String containing the mpint
 * \returns NULL otherwise
 */

struct string_struct *buffer_get_mpint(struct buffer_struct *buffer) {
  u16 bits;
  u32 len;
  struct string_struct *str = NULL;

  if (buffer_get_data(buffer, &bits, sizeof(u16)) != sizeof(u16)) {
    return NULL;
  }
  bits = ntohs(bits);
  len = (bits + 7) / 8;
  if ((buffer->pos + len) > buffer->used) {
    return NULL;
  }
  str = string_new(len);
  if (str == NULL) {
    return NULL;
  }
  if (buffer_get_data(buffer, str->string, len) != len) {
    SAFE_FREE(str);
    return NULL;
  }
  return str;
}
/** @} */
/* vim: set ts=2 sw=2 et cindent: */
