/* server.c */
/*
Copyright 2004,2005 Aris Adamantiadis

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
#include <stdlib.h>
#include "libssh/libssh.h"
#include "libssh/server.h"
#include "libssh/ssh2.h"
static int bind_socket(SSH_BIND *ssh_bind,char *hostname, int port) {
    struct sockaddr_in myaddr;
    int opt = 1;
    int s = socket(PF_INET, SOCK_STREAM, 0);
    struct hostent *hp=NULL;
#ifdef HAVE_GETHOSTBYNAME
    hp=gethostbyname(hostname);
#endif
    if(!hp){
        ssh_set_error(ssh_bind,SSH_FATAL,"resolving %s: %s",hostname,hstrerror(h_errno));
        close(s);
        return -1;
    }
    
    memset(&myaddr, 0, sizeof(myaddr));
    memcpy(&myaddr.sin_addr,hp->h_addr,hp->h_length);
    myaddr.sin_family=hp->h_addrtype;
    myaddr.sin_port = htons(port);
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(s, (struct sockaddr *) &myaddr, sizeof(myaddr)) < 0) {
        ssh_set_error(ssh_bind,SSH_FATAL,"Binding to %s:%d : %s",hostname,port,
                strerror(errno));
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
    fd=bind_socket(ssh_bind,host,ssh_bind->options->bindport);
    if(fd<0)
        return -1;
    ssh_bind->bindfd=fd;
    if(listen(fd,10)<0){
        ssh_set_error(ssh_bind,SSH_FATAL,"listening to socket %d: %s",
                fd,strerror(errno));
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
    PRIVATE_KEY *dsa=NULL, *rsa=NULL;
    if(ssh_bind->bindfd<0){
        ssh_set_error(ssh_bind,SSH_FATAL,"Can't accept new clients on a "
                "not bound socket.");
        return NULL;
    }
    if(!ssh_bind->options->dsakey && !ssh_bind->options->rsakey){
        ssh_set_error(ssh_bind,SSH_FATAL,"DSA or RSA host key file must be set before accept()");
        return NULL;
    }
    if(ssh_bind->options->dsakey){
        dsa=_privatekey_from_file(ssh_bind,ssh_bind->options->dsakey,TYPE_DSS);
        if(!dsa)
            return NULL;
        ssh_say(2,"Dsa private key read successfuly\n");
    }
    if(ssh_bind->options->rsakey){
        rsa=_privatekey_from_file(ssh_bind,ssh_bind->options->rsakey,TYPE_RSA);
        if(!rsa){
            if(dsa)
                private_key_free(dsa);
            return NULL;
        }
        ssh_say(2,"RSA private key read successfuly\n");
    }
    int fd=accept(ssh_bind->bindfd,NULL,NULL);
    if(fd<0){
        ssh_set_error(ssh_bind,SSH_FATAL,"Accepting a new connection: %s",
                strerror(errno));
        if(dsa)
            private_key_free(dsa);
        if(rsa)
            private_key_free(rsa);
        return NULL;
    }
    session=ssh_new();
    session->server=1;
    session->version=2;
    session->fd=fd;
    session->options=ssh_options_copy(ssh_bind->options);
    session->dsa_key=dsa;
    session->rsa_key=rsa;
    return session;
}

void ssh_bind_free(SSH_BIND *ssh_bind){
    if(ssh_bind->bindfd>=0)
        close(ssh_bind->bindfd);
    ssh_bind->bindfd=-1;
    free(ssh_bind);
}

extern char *supported_methods[];

int server_set_kex(SSH_SESSION * session) {
    KEX *server = &session->server_kex;
    SSH_OPTIONS *options = session->options;
    int i;
    char *wanted;
    memset(server,0,sizeof(KEX));
    // the program might ask for a specific cookie to be sent. useful for server
    //   debugging
    if (options->wanted_cookie)
        memcpy(server->cookie, options->wanted_cookie, 16);
    else
        ssh_get_random(server->cookie, 16,0);
    if(session->dsa_key && session->rsa_key){
        ssh_options_set_wanted_algos(options,SSH_HOSTKEYS,"ssh-dss,ssh-rsa");
    } else {
        if(session->dsa_key)
            ssh_options_set_wanted_algos(options,SSH_HOSTKEYS,"ssh-dss");
        else
            ssh_options_set_wanted_algos(options,SSH_HOSTKEYS,"ssh-rsa");
    }
    server->methods = malloc(10 * sizeof(char **));
    for (i = 0; i < 10; i++) {
        if (!(wanted = options->wanted_methods[i]))
            wanted = supported_methods[i];
        server->methods[i] = strdup(wanted);
        //printf("server->methods[%d]=%s\n",i,wanted);
    }
    return 0;
}

static int dh_handshake_server(SSH_SESSION *session){
    STRING *e,*f,*pubkey,*sign;
    PUBLIC_KEY *pub;
    PRIVATE_KEY *prv;
    BUFFER *buf=buffer_new();
    if(packet_wait(session, SSH2_MSG_KEXDH_INIT ,1))
        return -1;
    e=buffer_get_ssh_string(session->in_buffer);
    if(!e){
        ssh_set_error(session,SSH_FATAL,"No e number in client request");
        return -1;
    }
    dh_import_e(session,e);
    dh_generate_y(session);
    dh_generate_f(session);
    f=dh_get_f(session);
    switch(session->hostkeys){
        case TYPE_DSS:
            prv=session->dsa_key;
            break;
        case TYPE_RSA:
            prv=session->rsa_key;
            break;
        default:
            prv=NULL;
    }
    pub=publickey_from_privatekey(prv);
    pubkey=publickey_to_string(pub);
    publickey_free(pub);
    dh_import_pubkey(session,pubkey);
    dh_build_k(session);
    make_sessionid(session);
    sign=ssh_sign_session_id(session,prv);
    buffer_free(buf);
    /* free private keys as they should not be readable past this point */
    if(session->rsa_key){
        private_key_free(session->rsa_key);
        session->rsa_key=NULL;
    }
    if(session->dsa_key){
        private_key_free(session->dsa_key);
        session->dsa_key=NULL;
    }
    buffer_add_u8(session->out_buffer,SSH2_MSG_KEXDH_REPLY);
    buffer_add_ssh_string(session->out_buffer,pubkey);
    buffer_add_ssh_string(session->out_buffer,f);
    buffer_add_ssh_string(session->out_buffer,sign);
    free(sign);
    packet_send(session);
    free(f);
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH2_MSG_NEWKEYS);
    packet_send(session);
    ssh_say(2,"SSH_MSG_NEWKEYS sent\n");

    packet_wait(session,SSH2_MSG_NEWKEYS,1);
    ssh_say(2,"Got SSH_MSG_NEWKEYS\n");
    generate_session_keys(session);
    /* once we got SSH2_MSG_NEWKEYS we can switch next_crypto and current_crypto */
    if(session->current_crypto)
        crypto_free(session->current_crypto);
    /* XXX later, include a function to change keys */
    session->current_crypto=session->next_crypto;
    session->next_crypto=crypto_new();
    return 0;
}
/* do the banner and key exchange */
int ssh_accept(SSH_SESSION *session){
    ssh_send_banner(session,1);
    ssh_crypto_init();
    session->clientbanner=ssh_get_banner(session);
    server_set_kex(session);
    ssh_send_kex(session,1);
    if(ssh_get_kex(session,1))
        return -1;
    ssh_list_kex(&session->client_kex);
    crypt_set_algorithms_server(session);
    if(dh_handshake_server(session))
        return -1;
    session->connected=1;
    return 0;
}

