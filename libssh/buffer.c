/* buffer.c */
/* Well, buffers */
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
#include <string.h>
#include <netdb.h>
#include "libssh/priv.h"

/** defgroup ssh_buffer
 * \brief buffer handling
 */

/** \addtogroup ssh_buffer
 * @{
 */

/** \brief creates a new buffer
 * \return a new initialized buffer
 */
BUFFER *buffer_new(){
    BUFFER *buffer=malloc(sizeof(BUFFER));
    memset(buffer,0,sizeof(BUFFER));
    return buffer;
    }

/** \brief desallocate a buffer
 * \param buffer buffer to free
 */
void buffer_free(BUFFER *buffer){
//    printf("buffer %p : free(%p);\n",buffer,buffer->data);
    if(buffer->data){
        memset(buffer->data,0,buffer->allocated); /* burn the data */
        free(buffer->data);
        }
    memset(buffer,'x',sizeof (*buffer));
    free(buffer);
    }

/* \internal
 * \brief reinitialize a buffer
 * \param buffer buffer
 */
void buffer_reinit(BUFFER *buffer){
    memset(buffer->data,0,buffer->used);
    buffer->used=0;
    buffer->pos=0;
}

static void realloc_buffer(BUFFER *buffer,int needed){
    needed=(needed+0x7f) & ~0x7f;
//    printf("buffer %p : realloc(%x,%d)=",buffer,buffer->data,needed);
    buffer->data=realloc(buffer->data,needed);
//    printf("%p\n",buffer->data);
    buffer->allocated=needed;
}
/** \internal
 * \brief add data at tail of the buffer
 * \param buffer buffer
 * \param data data pointer
 * \param len length of data
 */
void buffer_add_data(BUFFER *buffer,void *data,int len){
    if(buffer->allocated < buffer->used+len)
        realloc_buffer(buffer,buffer->used+len);
    memcpy(buffer->data+buffer->used,data,len);
    buffer->used+=len;
    }

void buffer_add_ssh_string(BUFFER *buffer,STRING *string){
    u32 len=ntohl(string->size);
    buffer_add_data(buffer,string,len+sizeof(u32));
    }

void buffer_add_u32(BUFFER *buffer,u32 data){
    buffer_add_data(buffer,&data,sizeof(data));
}

void buffer_add_u64(BUFFER *buffer,u64 data){
    buffer_add_data(buffer,&data,sizeof(data));
}

void buffer_add_u8(BUFFER *buffer,u8 data){
    buffer_add_data(buffer,&data,sizeof(u8));
}

/** \internal
 * \brief add data at head of a buffer
 * \param buffer buffer
 * \param data data to add
 * \param len length of data
 */
void buffer_add_data_begin(BUFFER *buffer, void *data, int len){
    if(buffer->allocated < buffer->used + len)
        realloc_buffer(buffer,buffer->used+len);
    memmove(buffer->data+len,buffer->data,buffer->used);
    memcpy(buffer->data,data,len);
    buffer->used+=len;
}

/** \internal
 * \brief append data from a buffer to tail of another
 * \param buffer destination buffer
 * \param source source buffer. Doesn't take position in buffer into account
 */
void buffer_add_buffer(BUFFER *buffer, BUFFER *source){
    buffer_add_data(buffer,buffer_get(source),buffer_get_len(source));
}

/** \brief get a pointer on the head of the buffer
 * \param buffer buffer
 * \return data pointer on the head. Doesn't take position into account.
 * \warning don't expect data to be nul-terminated
 * \see buffer_get_rest()
 * \see buffer_get_len()
 */
void *buffer_get(BUFFER *buffer){
    return buffer->data;
}

/** \internal
 * \brief get a pointer to head of the buffer at current position
 * \param buffer buffer
 * \return pointer to the data from current position
 * \see buffer_get_rest_len()
 * \see buffer_get()
 */
void *buffer_get_rest(BUFFER *buffer){
    return buffer->data+buffer->pos;
}

/** \brief get length of the buffer, not counting position
 * \param buffer
 * \return length of the buffer
 * \see buffer_get()
 */
int buffer_get_len(BUFFER *buffer){
    return buffer->used;
}

/** \internal
 *  \brief get length of the buffer from the current position
 * \param buffer
 * \return length of the buffer
 * \see buffer_get_rest()
 */
int buffer_get_rest_len(BUFFER *buffer){
    return buffer->used - buffer->pos;
}

/** \internal
 * has effect to "eat" bytes at head of the buffer 
 * \brief advance the position in the buffer
 * \param buffer buffer
 * \param len number of bytes to eat
 * \return new size of the buffer
 */
int buffer_pass_bytes(BUFFER *buffer,int len){
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
int buffer_pass_bytes_end(BUFFER *buffer,int len){
    if(buffer->used < buffer->pos + len)
        return 0;
    buffer->used-=len;
    return len;
}

int buffer_get_data(BUFFER *buffer, void *data, int len){
    if(buffer->pos+len>buffer->used)
        return 0;  /*no enough data in buffer */
    memcpy(data,buffer->data+buffer->pos,len);
    buffer->pos+=len;
    return len;   /* no yet support for partial reads (is it really needed ?? ) */
}    

int buffer_get_u8(BUFFER *buffer, u8 *data){
    return buffer_get_data(buffer,data,sizeof(u8));
}

int buffer_get_u32(BUFFER *buffer, u32 *data){
    return buffer_get_data(buffer,data,sizeof(u32));
}

int buffer_get_u64(BUFFER *buffer, u64 *data){
    return buffer_get_data(buffer,data,sizeof(u64));
}

STRING *buffer_get_ssh_string(BUFFER *buffer){
    u32 stringlen;
    u32 hostlen;
    STRING *str;
    if(buffer_get_u32(buffer,&stringlen)==0)
        return NULL;
    hostlen=ntohl(stringlen);
    /* verify if there is enough space in buffer to get it */
    if(buffer->pos+hostlen>buffer->used)
        return NULL; /* it is indeed */
    str=string_new(hostlen);
    if(buffer_get_data(buffer,str->string,hostlen)!=hostlen){
        ssh_say(0,"buffer_get_ssh_string: oddish : second test failed when first was successful. len=%d",hostlen);
        free(str);
        return NULL;
        }
    return str;
}

/* this one is SSH-1 only */
STRING *buffer_get_mpint(BUFFER *buffer){
    u16 bits;
    u32 len;
    STRING *str;
    if(buffer_get_data(buffer,&bits,sizeof(u16))!= sizeof(u16))
        return NULL;
    bits=ntohs(bits);
    len=(bits+7)/8;
    if(buffer->pos+len > buffer->used)
        return NULL;
    str=string_new(len);
    if(buffer_get_data(buffer,str->string,len)!=len){
        free(str);
        return NULL;
    }
    return str;
}
/** @} */

