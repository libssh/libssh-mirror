/*
Copyright 2005 Aris Adamantiadis

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

#include "server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
list *list_add(list *ptr, const char *key, void *data){
    list *new=malloc(sizeof(list));
    new->next=ptr;
    new->data=data;
    new->key=strdup(key);
    return new;
}

void *list_find(list *ptr, const char *key){
    while(ptr){
        if(!strcmp(key,ptr->key))
            return ptr->data;
        ptr=ptr->next;
    }
    return NULL;
}

void list_set(list *ptr, const char *key, void *data){
    while(ptr){
        if(!strcmp(key,ptr->key)){
            ptr->data=data;
            return;
        }
        ptr=ptr->next;
    }
}
