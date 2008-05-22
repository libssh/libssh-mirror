/* socket.c */
/* the Socket class */
/*
 * Copyright 2008 Aris Adamantiadis
 *
 * This file is part of the SSH Library
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
 * MA 02111-1307, USA. */

#include <unistd.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "libssh/priv.h"

struct socket {
	socket_t fd;
	int last_errno;
};

/*
 * \internal
 * \brief inits the socket system (windows specific)
 */
void ssh_socket_init(){
#ifdef _WIN32
    struct WSAData wsaData;
    if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
        ssh_say(1,"Error initialising Windows sockets.\n");
    }
#endif
}
/*
 * \internal
 * \brief creates a new Socket object
 */
struct socket *ssh_socket_new(){
	struct socket *s=malloc(sizeof(struct socket));
	s->fd=-1;
	s->last_errno=-1;
	return s;
}

/* \internal
 * \brief Deletes a socket object
 */
void ssh_socket_free(struct socket *s){
    ssh_socket_close(s);
	free(s);
}

/* \internal
 * \brief closes a socket
 */
void ssh_socket_close(struct socket *s){
	if(ssh_socket_is_open(s)){
#ifdef _WIN32
		closesocket(s->fd);
		s->last_errno=WSAGetLastError();
#else
		close(s->fd);
		s->last_errno=errno;
#endif		
		s->fd=-1;
	}
}

/* \internal
 * \brief sets the file descriptor of the socket
 */
void ssh_socket_set_fd(struct socket *s, socket_t fd){
	s->fd=fd;
}

/* \internal
 * \brief returns the file descriptor of the socket
 */
socket_t ssh_socket_get_fd(struct socket *s){
	return s->fd;
}

/* \internal
 * \brief returns nonzero if the socket is open
 */
int ssh_socket_is_open(struct socket *s){
	return s->fd != -1;
}

/* \internal
 * \brief read len bytes from socket into buffer
 */
int ssh_socket_read(struct socket *s, void *buffer, int len){
	int r=recv(s->fd,buffer,len,0);
#ifndef _WIN32	
    s->last_errno=errno;
#else
    s->last_errno=WSAGetLastError();
#endif	
	return r;
}

/* \internal
 * \brief writes len bytes from byffer to socket
 */
int ssh_socket_write(struct socket *s,const void *buffer, int len){
	int w=send(s->fd,buffer,len,0);
#ifndef _WIN32
    s->last_errno=errno;
#else
    s->last_errno=WSAGetLastError();
#endif

	return w;
}

/* \internal
 * \brief returns nonzero if the current socket is in the fd_set
 */
int ssh_socket_fd_isset(struct socket *s, fd_set *set){
	if(s->fd==-1)
		return 0;
	return FD_ISSET(s->fd,set);
}

/* \internal
 * \brief sets the current fd in a fd_set and updates the fd_max
 */

void ssh_socket_fd_set(struct socket *s, fd_set *set, int *fd_max){
	if(s->fd==-1)
		return;
	FD_SET(s->fd,set);
	if(s->fd>= *fd_max){
		*fd_max=s->fd+1;
	}
}

/* \internal
 * \brief reads blocking until len bytes have been read
 */
int ssh_socket_completeread(struct socket *s, void *buffer, int len){
    int r;
    int total=0;
    int toread=len;
    if(!ssh_socket_is_open(s))
        return SSH_ERROR;
    while((r=ssh_socket_read(s,buffer+total,toread))){
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
