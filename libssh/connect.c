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
#include <stdio.h>
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

#ifndef HAVE_SELECT
#error "Your system must have select()"
#endif

#ifndef HAVE_GETADDRINFO
#error "Your system must have getaddrinfo()"
#endif

static void sock_set_nonblocking(int sock) {
    fcntl(sock,F_SETFL,O_NONBLOCK);
}
static void sock_set_blocking(int sock){
    fcntl(sock,F_SETFL,0);
}

static int getai(const char *host, int port, struct addrinfo **ai)
{
    struct addrinfo hints;
    char *service=NULL;
    char s_port[10];
   
    memset(&hints,0,sizeof(hints));
    hints.ai_protocol=IPPROTO_TCP;
    hints.ai_family=PF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    if(port==0){
        hints.ai_flags=AI_PASSIVE;
    } else {
        snprintf(s_port,sizeof(s_port),"%hu",port);
	service=s_port;
    }
    return getaddrinfo(host,service,&hints,ai);
}

int ssh_connect_ai_timeout(SSH_SESSION *session, const char *host, int port, struct addrinfo *ai,
                           long timeout, long usec,int s)
{
    struct timeval to;
    fd_set set;
    int ret=0;
    unsigned int len=sizeof(ret);
    to.tv_sec=timeout;
    to.tv_usec=usec;
    sock_set_nonblocking(s);
    connect(s,ai->ai_addr,ai->ai_addrlen);
    freeaddrinfo(ai);
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

/* connect_host connects to an IPv4 (or IPv6) host */
/* specified by its IP address or hostname. */
/* output is the file descriptor, <0 if failed. */

int ssh_connect_host(SSH_SESSION *session, const char *host, const char 
        *bind_addr, int port,long timeout, long usec){
    int s=-1;
    int my_errno;
    struct addrinfo *ai, *ai2;

    my_errno=getai(host, port, &ai);
    if (my_errno){
        ssh_set_error(session,SSH_FATAL,"Failed to resolve hostname %s (%s)",host,gai_strerror(my_errno));
        return -1;
    }
    
    for(ai2=ai;ai2!=NULL;ai2=ai2->ai_next){
        /* create socket */
        s=socket(ai2->ai_family,ai2->ai_socktype,ai2->ai_protocol);
        if(s<0){
            ssh_set_error(session,SSH_FATAL,"socket : %s",strerror(errno));
            continue;
        }

        if(bind_addr){
            struct addrinfo *bind_ai, *bind_ai2;

            ssh_say(2,"resolving %s\n",bind_addr);
            my_errno=getai(host,0,&bind_ai);
            if (my_errno){
                ssh_set_error(session,SSH_FATAL,"Failed to resolve bind address %s (%s)",bind_addr,gai_strerror(my_errno));
                return -1;
            }

            for(bind_ai2=bind_ai;bind_ai2!=NULL;bind_ai2=bind_ai2->ai_next){
                if(bind(s,bind_ai2->ai_addr,bind_ai2->ai_addrlen)<0){
                    ssh_set_error(session,SSH_FATAL,"Binding local address : %s",strerror(errno));
                    continue;
                }    
		else{
                    break;
		}
            }
            freeaddrinfo(bind_ai);
            if(bind_ai2==NULL){ /*cannot bind to any local addresses*/
                close(s);
                s=-1;
                continue;
            }
        }
        if(timeout||usec){
            return ssh_connect_ai_timeout(session,host,port,ai2,timeout,usec,s);
        }
        if(connect(s,ai2->ai_addr,ai2->ai_addrlen)<0){
            ssh_set_error(session,SSH_FATAL,"connect: %s",strerror(errno));
            close(s);
            s=-1;
            continue;
        }
        else{ /*we are connected*/
            break;
        }
    }
    freeaddrinfo(ai);
    return s;
}

/** \addtogroup ssh_session
 *  * @{ */

/** \internal
 * \brief polls the stream for activity
 * \param session ssh session
 * \param write value pointed to set to 1 if it is possible to write
 * \param except value pointed to set to 1 if there is an exception
 * \return 1 if it is possible to read, 0 otherwise, -1 on error
 */
int ssh_fd_poll(SSH_SESSION *session, int *write, int *except){
    struct timeval sometime;
    fd_set rdes; // read set
    fd_set wdes; // writing set
    fd_set edes; // exception set
    
    FD_ZERO(&rdes);
    FD_ZERO(&wdes);
    FD_ZERO(&edes);
    
    if(!session->alive || session->fd<0){
        *except=1;
        *write=0;
        session->alive=0;
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


/** This functions acts more or less like the select(2) syscall.\n
 * There is no support for writing or exceptions.\n
 * \brief wrapper for the select syscall
 * \param channels arrays of channels pointers finished by an NULL. It is never rewritten/
 * \param outchannels arrays of same size that "channels", it hasn't to be initialized
 * \param maxfd maximum +1 file descriptor from readfds
 * \param readfds an fd_set of file descriptors to be select'ed for reading
 * \param timeout a timeout for the select
 * \see select(2)
 * \return -1 if an error occured. E_INTR if it was interrupted. In that case, just restart it.
 * \warning libssh is not threadsafe. That means that if a signal is caught during the processing
 * of this function, you cannot call ssh functions on sessions that are busy with ssh_select()
 */
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
        if(channels[i]->session->alive){
            if(channel_poll(channels[i],0)>0){
                outchannels[j]=channels[i];
                j++;
            } else
            if(channel_poll(channels[i],1)>0){
                outchannels[j]=channels[i];
                j++;
            }
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
        if(channels[i]->session->alive && FD_ISSET(channels[i]->session->fd,&localset))
            channels[i]->session->data_to_read=1;
            
    /* now, test each channel */
    j=0;
    for(i=0;channels[i];i++){
        if(channels[i]->session->alive && FD_ISSET(channels[i]->session->fd,&localset))
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

/** @} */
