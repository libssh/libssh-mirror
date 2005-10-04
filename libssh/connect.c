/* connect.c */
/* it handles connections to ssh servers */
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

#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "libssh/priv.h"

#ifndef HAVE_GETHOSTBYNAME
#ifndef HAVE_GETHOSTBYADDR
#error "your system doesn't have gethostbyname nor gethostbyaddr"
#endif
#endif
#ifndef HAVE_SELECT
#error "Your system must have select()"
#endif

static void sock_set_nonblocking(int sock) {
    fcntl(sock,F_SETFL,O_NONBLOCK);
}
static void sock_set_blocking(int sock){
    fcntl(sock,F_SETFL,0);
}

/* connect_host connects to an IPv4 (or IPv6) host */
/* specified by its IP address or hostname. */
/* output is the file descriptor, <0 if failed. */

int ssh_connect_host(SSH_SESSION *session, const char *host, const char 
        *bind_addr, int port,long timeout, long usec){
    struct sockaddr_in sa;
    struct sockaddr_in bindsa;
    struct hostent *hp=NULL;
    static int count=0; /* for reentrencity */
    int s;
    while(++count>1)
        --count;

#ifdef HAVE_GETHOSTBYNAME
    hp=gethostbyname(host);
#endif
    if(!hp){
        --count;
        ssh_set_error(session,SSH_FATAL,"Failed to resolve hostname %s (%s)",host,hstrerror(h_errno));
        return -1;
    }
    memset(&sa,0,sizeof(sa));
    memcpy(&sa.sin_addr,hp->h_addr,hp->h_length);
    sa.sin_family=hp->h_addrtype;
    sa.sin_port=htons((unsigned short)port);
    --count;
    
    if(bind_addr){
        ssh_say(2,"resolving %s\n",bind_addr);
        hp=NULL;
        while(++count>1)
            --count;
#ifdef HAVE_GETHOSTBYADDR
        hp=gethostbyaddr(bind_addr,4,AF_INET);
#endif
#ifdef HAVE_GETHOSTBYNAME
        if(!hp)
            hp=gethostbyname(bind_addr);
#endif
        if(!hp){
            --count;
            ssh_set_error(session,SSH_FATAL,"Failed to resolve bind address %s (%s)",bind_addr,hstrerror(h_errno));
            return -1;
        }
    }
    memset(&bindsa,0,sizeof(bindsa));
    /* create socket */
    s=socket(sa.sin_family,SOCK_STREAM,0);
    if(s<0){
        if(bind_addr)
            --count;
        ssh_set_error(session,SSH_FATAL,"socket : %s",strerror(errno));
        return s;
    }

    if(bind_addr){
        memcpy(&bindsa.sin_addr,hp->h_addr,hp->h_length);
        bindsa.sin_family=hp->h_addrtype;
        --count;
        if(bind(s,(struct sockaddr *)&bindsa,sizeof(bindsa))<0){
            ssh_set_error(session,SSH_FATAL,"Binding local address : %s",strerror(errno));
            close(s);
            return -1;
        }
    }
    if(timeout){
        struct timeval to;
        fd_set set;
        int ret=0;
        unsigned int len=sizeof(ret);
        to.tv_sec=timeout;
        to.tv_usec=usec;
        sock_set_nonblocking(s);
        connect(s,(struct sockaddr* )&sa,sizeof(sa));
        FD_ZERO(&set);
        FD_SET(s,&set);
        ret=select(s+1,NULL,&set,NULL,&to);
        if(ret==0){
            /* timeout */
            ssh_set_error(session,SSH_FATAL,"Timeout while connecting to %s:%d",host,port);
            close(s);
            return -1;
        }
        if(ret<0){
            ssh_set_error(session,SSH_FATAL,"Select error : %s",strerror(errno));
            close(s);
            return -1;
        }
        /* get connect(2) return code. zero means no error */
        getsockopt(s,SOL_SOCKET,SO_ERROR,&ret,&len);
        if (ret!=0){
            ssh_set_error(session,SSH_FATAL,"Connecting : %s",strerror(ret));
            close(s);
            return -1;
        }
        /* s is connected ? */
        ssh_say(3,"socket connected with timeout\n");
        sock_set_blocking(s);
        return s;
    }
    if(connect(s,(struct sockaddr *)&sa,sizeof(sa))< 0){
        close(s);
        ssh_set_error(session,SSH_FATAL,"connect: %s",strerror(errno));
        return -1;
    }
    return s;
}

/* returns 1 if bytes are available to read on the stream, 0 instead */
/* -1 on select() error. */
int ssh_fd_poll(SSH_SESSION *session, int *write, int *except){
    struct timeval sometime;
    fd_set rdes; // read set
    fd_set wdes; // writing set
    fd_set edes; // exception set
    
    FD_ZERO(&rdes);
    FD_ZERO(&wdes);
    FD_ZERO(&edes);
    
    if(!session->alive){
        *except=1;
        *write=0;
        return 0;
    }
    if(!session->data_to_read)
        FD_SET(session->fd,&rdes);
    if(!session->data_to_write)
        FD_SET(session->fd,&wdes);
    FD_SET(session->fd,&edes);
    
    /* Set to return immediately (no blocking) */
    sometime.tv_sec = 0;
    sometime.tv_usec = 0;
    
    /* Make the call, and listen for errors */
    if (select(session->fd + 1, &rdes,&wdes,&edes, &sometime) < 0) {
    	ssh_set_error(NULL,SSH_FATAL, "select: %s", strerror(errno));
    	return -1;
    }
    if(!session->data_to_read)
        session->data_to_read=FD_ISSET(session->fd,&rdes);
    if(!session->data_to_write)
        session->data_to_write=FD_ISSET(session->fd,&wdes);
    *except=FD_ISSET(session->fd,&edes);
    *write=session->data_to_write;
    return session->data_to_read;
}

/* this function is a complete wrapper for the select syscall. it does more than wrapping ... */
int ssh_select(CHANNEL **channels,CHANNEL **outchannels, int maxfd, fd_set *readfds, struct timeval *timeout){
    struct timeval zerotime;
    fd_set localset,localset2;
    int rep;
    int i,j;
    int set;

    zerotime.tv_sec=0;
    zerotime.tv_usec=0;
    /* first, poll the maxfd file descriptors from the user with a zero-second timeout. they have the bigger priority */
    if(maxfd>0){
        memcpy(&localset,readfds, sizeof(fd_set));
        rep=select(maxfd,&localset,NULL,NULL,&zerotime);
        // catch the eventual errors
        if(rep==-1)
            return -1;
    }
    j=0;
    // polls every channel.
    for(i=0;channels[i];i++){
        if(channel_poll(channels[i],0)>0){
            outchannels[j]=channels[i];
            j++;
        } else
        if(channel_poll(channels[i],1)>0){
            outchannels[j]=channels[i];
            j++;
        }
    }
    outchannels[j]=NULL;
    /* look into the localset for active fd */
    set=0;
    for(i=0;(i<maxfd) && !set;i++)
        if(FD_ISSET(i,&localset))
            set=1;
    // j!=0 means a channel has data
    if( (j!=0) || (set!=0)){
        if(maxfd>0)
            memcpy(readfds,&localset,sizeof(fd_set));
        return 0;
    }
    /* at this point, not any channel had any data ready for reading, nor any fd had data for reading */
    memcpy(&localset,readfds,sizeof(fd_set));
    for(i=0;channels[i];i++){
        if(channels[i]->session->alive){
            FD_SET(channels[i]->session->fd,&localset);
            if(channels[i]->session->fd>maxfd-1)
                maxfd=channels[i]->session->fd+1;
        }
    }
    rep=select(maxfd,&localset,NULL,NULL,timeout);
    if(rep==-1 && errno==EINTR){
        return SSH_EINTR; /* interrupted by a signal */
    }
    if(rep==-1){
        /* was the error due to a libssh's Channel or from a closed descriptor from the user ? user closed descriptors have been
        caught in the first select and not closed since that moment. that case shouldn't occur at all */
        return -1;
    }
    /* set the data_to_read flag on each session */
    for(i=0;channels[i];i++)
        if(FD_ISSET(channels[i]->session->fd,&localset))
            channels[i]->session->data_to_read=1;
            
    /* now, test each channel */
    j=0;
    for(i=0;channels[i];i++){
        if(FD_ISSET(channels[i]->session->fd,&localset))
            if((channel_poll(channels[i],0)>0) || (channel_poll(channels[i],1)>0)){
                outchannels[j]=channels[i];
                j++;
            }
    }
    outchannels[j]=NULL;
    FD_ZERO(&localset2);
    for(i=0;i<maxfd;i++)
        if(FD_ISSET(i,readfds) && FD_ISSET(i,&localset))
            FD_SET(i,&localset2);
    memcpy(readfds,&localset2,sizeof(fd_set));
    return 0;
}
