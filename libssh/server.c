/* server.c */

/* No. It doesn't work yet. It's just hard to have 2 separated trees, one for releases 
 * and one for development */
/*
Copyright 2004 Aris Adamantiadis

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

/* from times to times, you need to serve your friends */
/* and, perhaps, ssh connections. */

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include "libssh/libssh.h"
#include "libssh/server.h"
static int bind_socket(char *hostname, int port) {
    struct sockaddr_in myaddr;
    int opt = 1;
    int s = socket(PF_INET, SOCK_STREAM, 0);
    struct hostent *hp=NULL;
#ifdef HAVE_GETHOSTBYADDR
    hp=gethostbyaddr(hostname,4,AF_INET);
#endif
#ifdef HAVE_GETHOSTBYNAME
    if(!hp)
        hp=gethostbyname(hostname);
#endif
    if(!hp){
        close(s);
        return -1;
    }
    
    memset(&myaddr, 0, sizeof(myaddr));
    memcpy(&myaddr.sin_addr,hp->h_addr,hp->h_length);
    myaddr.sin_family=hp->h_addrtype;
    myaddr.sin_port = htons(port);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(s, (struct sockaddr *) &myaddr, sizeof(myaddr)) < 0) {
	    close(s);
        return -1;
    }
    return s;
}

SSH_BIND *ssh_bind_new(){
    SSH_BIND *ptr=malloc(sizeof(SSH_BIND));
    memset(ptr,0,sizeof(*ptr));
    ptr->bindfd=-1;
    return ptr;
}

void ssh_bind_set_options(SSH_BIND *ssh_bind, SSH_OPTIONS *options){
    ssh_bind->options=options;
}

int ssh_bind_listen(SSH_BIND *ssh_bind){
    char *host;
    int fd;
    if(!ssh_bind->options)
        return -1;
    host=ssh_bind->options->bindaddr;
    if(!host)
        host="0.0.0.0";
    fd=bind_socket(host,ssh_bind->options->bindport);
    if(fd<0)
        return -1;
    ssh_bind->bindfd=fd;
    if(listen(fd,10)<0){
        close(fd);
        return -1;
    }
    return 0;
}

void ssh_bind_set_blocking(SSH_BIND *ssh_bind, int blocking){
    ssh_bind->blocking=blocking?1:0;
}

int ssh_bind_get_fd(SSH_BIND *ssh_bind){
    return ssh_bind->bindfd;
}

void ssh_bind_fd_toaccept(SSH_BIND *ssh_bind){
    ssh_bind->toaccept=1;
}

SSH_SESSION *ssh_bind_accept(SSH_BIND *ssh_bind){
    SSH_SESSION *session;
    if(ssh_bind->bindfd<0)
        return NULL;
    int fd=accept(ssh_bind->bindfd,NULL,NULL);
    if(fd<0)
        return NULL;
    session=ssh_new(ssh_options_copy(ssh_bind->options));
    session->server=1;
    session->fd=fd;
    return session;
}

/*
  
SSH_SESSION *getserver(SSH_OPTIONS * options) {
    int socket;
    int fd;
    SSH_SESSION *session;
    socket = bind_socket();
    if (socket < 0)
        return NULL;
    if (listen_socket(socket) < 0)
        return NULL;
    fd = accept_socket(socket);
    close(socket);
    if (fd < 0) {
        return NULL;
    }
    session = malloc(sizeof(SSH_SESSION));
    memset(session, 0, sizeof(SSH_SESSION));
    session->fd = fd;
    session->options = options;
    ssh_send_banner(session);
    return session;
}

extern char *supported_methods[];
int server_set_kex(SSH_SESSION * session) {
    KEX *server = &session->server_kex;
    SSH_OPTIONS *options = session->options;
    int i;
    char *wanted;
    if (!options) {
        ssh_set_error(session, SSH_FATAL,
		      "Options structure is null(client's bug)");
	return -1;
    }
    memset(server,0,sizeof(KEX));
    // the program might ask for a specific cookie to be sent. useful for server
    //   debugging
    if (options->wanted_cookie)
        memcpy(server->cookie, options->wanted_cookie, 16);
    else
        ssh_get_random(server->cookie, 16);
    server->methods = malloc(10 * sizeof(char **));
    for (i = 0; i < 10; i++) {
	if (!(wanted = options->wanted_methods[i]))
	    wanted = supported_methods[i];
	server->methods[i] = wanted;
    printf("server->methods[%d]=%s\n",i,wanted);
	if (!server->methods[i]) {
	    ssh_set_error(session, SSH_FATAL, 
	    	"kex error : did not find algo");
	    return -1;
	}
    return 0;
}

*/

