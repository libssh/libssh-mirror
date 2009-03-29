/*
 * connect.c - handles connections to ssh servers
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

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#ifdef _WIN32
#define _WIN32_WINNT 0x0501 //getaddrinfo, freeaddrinfo, getnameinfo
#include <winsock2.h>
#include <ws2tcpip.h>
#include "wspiapi.h" //workaround for w2k systems
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#endif
#include <fcntl.h>
#include "libssh/priv.h"

#ifndef HAVE_SELECT
#error "Your system must have select()"
#endif

#ifndef HAVE_GETADDRINFO
#error "Your system must have getaddrinfo()"
#endif

#ifndef _WIN32
static void sock_set_nonblocking(socket_t sock) {
    fcntl(sock,F_SETFL,O_NONBLOCK);
}
static void sock_set_blocking(socket_t sock){
    fcntl(sock,F_SETFL,0);
}
#else
static void sock_set_nonblocking(socket_t sock) {
        u_long nonblocking = 1;
        ioctlsocket(sock, FIONBIO, &nonblocking);
}
static void sock_set_blocking(socket_t sock){
        u_long nonblocking = 0;
        ioctlsocket(sock, FIONBIO, &nonblocking);
}

#ifndef gai_strerror
char WSAAPI *gai_strerrorA(int code){
     static char buffer[256];
     snprintf(buffer,256,"Undetermined error code (%d)",code);
     return buffer;
}
#endif

#endif

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

static int ssh_connect_ai_timeout(SSH_SESSION *session, const char *host,
    int port, struct addrinfo *ai, long timeout, long usec,socket_t s)
{
    struct timeval to;
    fd_set set;
    int ret=0;
    unsigned int len=sizeof(ret);
    enter_function();
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
        leave_function();
        return -1;
    }
    if(ret<0){
        ssh_set_error(session,SSH_FATAL,"Select error : %s",strerror(errno));
        close(s);
        leave_function();
        return -1;
    }
    ret = 0;
    /* get connect(2) return code. zero means no error */
    getsockopt(s,SOL_SOCKET,SO_ERROR,(char *)&ret,&len);
    if (ret!=0){
        ssh_set_error(session,SSH_FATAL,"Connecting : %s",strerror(ret));
        close(s);
        leave_function();
        return -1;
    }
    /* s is connected ? */
    ssh_log(session,SSH_LOG_PACKET,"socket connected with timeout\n");
    sock_set_blocking(s);
    leave_function();
    return s;
}

/** \internal
 * \brief connect_host connects to an IPv4 (or IPv6) host
 * specified by its IP address or hostname.
 * \returns file descriptor
 * \returns less than 0 value
 */

socket_t ssh_connect_host(SSH_SESSION *session, const char *host, const char
        *bind_addr, int port,long timeout, long usec){
    socket_t s=-1;
    int my_errno;
    struct addrinfo *ai, *ai2;
    enter_function();
    my_errno=getai(host, port, &ai);
    if (my_errno){
        ssh_set_error(session,SSH_FATAL,"Failed to resolve hostname %s (%s)",host,gai_strerror(my_errno));
        leave_function();
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

            ssh_log(session,SSH_LOG_PACKET,"resolving %s\n",bind_addr);
            my_errno=getai(host,0,&bind_ai);
            if (my_errno){
                ssh_set_error(session,SSH_FATAL,"Failed to resolve bind address %s (%s)",bind_addr,gai_strerror(my_errno));
                leave_function();
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
            socket_t ret=ssh_connect_ai_timeout(session,host,port,ai2,timeout,usec,s);
            leave_function();
            return ret;
        }
        if(connect(s,ai2->ai_addr,ai2->ai_addrlen)<0){
            ssh_set_error(session,SSH_FATAL,"connect: %s",strerror(errno));
            close(s);
            s=-1;
            leave_function();
            continue;
        }
        else{ /*we are connected*/
            break;
        }
    }
    freeaddrinfo(ai);
    leave_function();
    return s;
}

/** \addtogroup ssh_session
 *  * @{ */

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
int ssh_select(CHANNEL **channels,CHANNEL **outchannels, socket_t maxfd, fd_set *readfds, struct timeval *timeout){
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
            ssh_socket_fd_set(channels[i]->session->socket,&localset,&maxfd);
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
        if(channels[i]->session->alive && ssh_socket_fd_isset(channels[i]->session->socket,&localset))
            ssh_socket_set_toread(channels[i]->session->socket);

    /* now, test each channel */
    j=0;
    for(i=0;channels[i];i++){
        if(channels[i]->session->alive && ssh_socket_fd_isset(channels[i]->session->socket,&localset))
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
