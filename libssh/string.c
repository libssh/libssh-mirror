/*
 * string.c - ssh string functions
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
#include <unistd.h>
#include <string.h>
#include "libssh/priv.h"

/** \defgroup ssh_string SSH Strings
 * \brief string manipulations
 */
/** \addtogroup ssh_string
 * @{ */

/**
 * \brief Creates a new SSH String object
 * \param size size of the string
 * \return the newly allocated string
 */
STRING *string_new(unsigned int size){
    STRING *str=malloc(size + 4);
    str->size=htonl(size);
    return str;
}

void string_fill(STRING *str, const void *data,int len){
    memcpy(str->string,data,len);
}

/**
 * \brief Creates a ssh stream using a C string
 * \param what source 0-terminated C string
 * \return the newly allocated string.
 * \warning The nul byte is not copied nor counted in the ouput string.
 */
STRING *string_from_char(const char *what){
	STRING *ptr;
	int len=strlen(what);
	ptr=malloc(4 + len);
	ptr->size=htonl(len);
	memcpy(ptr->string,what,len);
	return ptr;
}

/**
 * \brief returns the size of a SSH string
 * \param str the input SSH string
 * \return size of the content of str
 */
u32 string_len(STRING *str){
	return ntohl(str->size);
}

/**
 * \brief convert a SSH string to a C nul-terminated string
 * \param str the input SSH string
 * \return a malloc'ed string pointer.
 * \warning If the input SSH string contains zeroes, some parts of
 * the output string may not be readable with regular libc functions.
 */
char *string_to_char(STRING *str){
    int len=ntohl(str->size)+1;
    char *string=malloc(len);
    memcpy(string,str->string,len-1);
    string[len-1]=0;
    return string;
}

STRING *string_copy(STRING *str){
    STRING *ret=malloc(ntohl(str->size)+4);
    ret->size=str->size;
    memcpy(ret->string,str->string,ntohl(str->size));
    return ret;
}

/** \brief destroy data in a string so it couldn't appear in a core dump
 * \param s string to burn
 */
void string_burn(STRING *s){
    memset(s->string,'X',string_len(s));
}

void *string_data(STRING *s){
    return s->string;
}

/**
 * \brief deallocate a STRING object
 * \param s String to delete
 */
void string_free(STRING *s){
	free(s);
}

/** @} */
