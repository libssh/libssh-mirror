/* options.c */
/* handle pre-connection options */
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include "libssh/priv.h"

/** defgroup ssh_options
 * \brief options settings for a new ssh session
 */
/** \addtogroup ssh_options
 * @{ */

/** This structure is freed automaticaly by ssh_disconnect()
 * when you use it. \n
 * It can be used by only one ssh_connect(), not more.\n
 * also by default, ssh1 support is not allowed 
 *
 * \brief initializes a new option structure
 * \returns an empty intialized option structure.
 * \see ssh_options_getopt()
*/

SSH_OPTIONS *ssh_options_new(){
    SSH_OPTIONS *option=malloc(sizeof(SSH_OPTIONS));
    memset(option,0,sizeof(SSH_OPTIONS));
    option->port=22; /* set the default port */
    option->fd=-1;
    option->ssh2allowed=1;
#ifdef HAVE_SSH1
    option->ssh1allowed=1;
#else
    option->ssh1allowed=0;
#endif
    option->bindport=22;
    return option;
}

/** \brief set port to connect or to bind for a connection
 * \param opt options structure
 * \param port port to connect or to bind
 */
void ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port){
    opt->port=port&0xffff;
    opt->bindport=port&0xffff;
}

/** you may need to duplication an option structure if you make several
 * sessions with the same options.\n
 * You cannot use twice the same option structure in ssh_session_connect.
 * \brief copies an option structure
 * \param opt option structure to copy
 * \returns new copied option structure
 * \see ssh_session_connect()
 */
SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt){
    SSH_OPTIONS *ret=ssh_options_new();    
    int i;
    ret->fd=opt->fd;
    ret->port=opt->port;
    if(opt->username)
        ret->username=strdup(opt->username);
    if(opt->host)
        ret->host=strdup(opt->host);
    if(opt->bindaddr)
        ret->host=strdup(opt->bindaddr);
    if(opt->identity)
        ret->identity=strdup(opt->identity);
    if(opt->ssh_dir)
        ret->ssh_dir=strdup(opt->ssh_dir);
    if(opt->known_hosts_file)
        ret->known_hosts_file=strdup(opt->known_hosts_file);
    if(opt->dsakey)
        ret->dsakey=strdup(opt->dsakey);
    if(opt->rsakey)
        ret->rsakey=strdup(opt->rsakey);
    for(i=0;i<10;++i)
        if(opt->wanted_methods[i])
            ret->wanted_methods[i]=strdup(opt->wanted_methods[i]);
    ret->passphrase_function=opt->passphrase_function;
    ret->connect_status_function=opt->connect_status_function;
    ret->connect_status_arg=opt->connect_status_arg;
    ret->timeout=opt->timeout;
    ret->timeout_usec=opt->timeout_usec;
    ret->ssh2allowed=opt->ssh2allowed;
    ret->ssh1allowed=opt->ssh1allowed;
    return ret;
}

/** \internal
 * \brief frees an option structure
 * \param opt option structure
 */
void ssh_options_free(SSH_OPTIONS *opt){
    int i;
    if(opt->username)
        free(opt->username);
    if(opt->identity)
        free(opt->identity);
    /* we don't touch the banner. if the implementation did use it, they have to free it */
    if(opt->host)
        free(opt->host);
    if(opt->bindaddr)
        free(opt->bindaddr);
    if(opt->ssh_dir)
        free(opt->ssh_dir);
    if(opt->dsakey)
        free(opt->dsakey);
    if(opt->rsakey)
        free(opt->rsakey);
    for(i=0;i<10;i++)
        if(opt->wanted_methods[i])
            free(opt->wanted_methods[i]);
    memset(opt,0,sizeof(SSH_OPTIONS));
    free(opt);
}

/** \brief set destination hostname
 * \param opt option structure
 * \param hostname host name to connect
 */
void ssh_options_set_host(SSH_OPTIONS *opt, const char *hostname){
    char *ptr=strdup(hostname);
    char *ptr2=strchr(ptr,'@');
    if(opt->host) // don't leak memory
        free(opt->host);
    if(ptr2){
        *ptr2=0;
        opt->host=strdup(ptr2+1);
        if(opt->username)
            free(opt->username);
        opt->username=strdup(ptr);
        free(ptr);
    } else
        opt->host=ptr;
}

/** \brief set username for authentication
 * \bug this should not be set at options time
 * \param opt options structure
 * \param username user name to authenticate
 */
void ssh_options_set_username(SSH_OPTIONS *opt, char *username){
    if(opt->username)
        free(opt->username);
    opt->username=strdup(username);
}

/** If you wish to open the socket yourself for a reason
 * or another, set the file descriptor.\n
 * don't forget to use ssh_option_set_hostname() as the hostname
 * is used as a key in the known_host mechanism
 * \brief set a file descriptor for connection
 * \param opt options structure
 * \param fd an opened file descriptor to use
 */
void ssh_options_set_fd(SSH_OPTIONS *opt, int fd){
    opt->fd=fd;
}

/** In case your client has multiple IP adresses, select the local address
 * and port to use for the socket.\n
 * If the address or port is not bindable, it may be impossible to
 * connect.
 * \brief set the local address and port binding
 * \param opt options structure
 * \param bindaddr bind address in form of hostname or ip address
 * \param port port number to bind
 */
void ssh_options_set_bind(SSH_OPTIONS *opt, char *bindaddr,int port){
    opt->bindaddr=strdup(bindaddr);
    opt->bindport=port;
}

/** the ssh directory is used for files like known_hosts and
 * identity (public and private keys)\n
 * \brief set the ssh directory
 * \param opt options structure
 * \param dir directory. It may include "%s" which will be replaced by
 * the user home directory
 * \see ssh_options_set_user_home_dir()
 */
void ssh_options_set_ssh_dir(SSH_OPTIONS *opt, char *dir){
    char buffer[1024];
    snprintf(buffer,1024,dir,ssh_get_user_home_dir());
    opt->ssh_dir=strdup(buffer);
}

/** the known hosts file is used to certify remote hosts are genuine.
 * \brief set the known hosts file name
 * \param opt options structure
 * \param dir path to the file including its name. "%s" will be substitued
 * with the user home directory
 * \see ssh_options_set_user_home_dir()
 */
void ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, char *dir){
    char buffer[1024];
    snprintf(buffer,1024,dir,ssh_get_user_home_dir());
    opt->known_hosts_file=strdup(buffer);
}

/** the identity file is used authenticate with public key.
 * \brief set the identity file name
 * \param opt options structure
 * \param identity path to the file including its name. "%s" will be substitued
 * with the user home directory
 * \see ssh_options_set_user_home_dir()
 */
void ssh_options_set_identity(SSH_OPTIONS *opt, char *identity){
    char buffer[1024];
    snprintf(buffer,1024,identity,ssh_get_user_home_dir());
    opt->identity=strdup(buffer);
}

/** \warning I don't remember what these functions are supposed
 * to set
 */
void ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, char *dsakey){
    opt->dsakey=strdup(dsakey);
}
/** \warning I don't remember what these functions are supposed
 * to set
 */
void ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, char *rsakey){
    opt->rsakey=strdup(rsakey);
}

/** \brief set the server banner sent to clients
 * \param opt options structure
 * \param banner a text banner to be shown
 */
void ssh_options_set_banner(SSH_OPTIONS *opt, char *banner){
    if(opt->banner)
        free(opt->banner);
    opt->banner=strdup(banner);
}

/** the methods are:\n
 * KEX_HOSTKEY (server public key type) : ssh-rsa or ssh-dss\n
 * KEX_CRYPT_C_S (symmetric cipher client to server)\n
 * KEX_CRYPT_S_C (symmetric cipher server to client)\n
 * KEX_COMP_C_S (Compression client to server): zlib or none\n
 * KEX_COMP_S_C (Compression server to client): zlib or none\n
 * You don't have to use this function if using the default ciphers
 * is okay for you\n
 * in order to enable compression client to server, do\n
 * ret=ssh_options_set_wanted_algos(opt,KEX_COMP_C_S,"zlib");
 * \brief set the algorithms to be used for cryptography and compression
 * \param opt options structure
 * \param algo method which needs to be changed
 * \param list list of algorithms to be used, in order of preference and separated by commas
 * \return 0 on success, -1 on error (most likely an algorithm is not available)
 */
int ssh_options_set_wanted_algos(SSH_OPTIONS *opt,int algo, char *list){
    if(algo > SSH_LANG_S_C || algo < 0){
        ssh_set_error(NULL,SSH_REQUEST_DENIED,"algo %d out of range",algo);
        return -1;
    }
    if( (!opt->use_nonexisting_algo) && !verify_existing_algo(algo,list)){
        ssh_set_error(NULL,SSH_REQUEST_DENIED,"Setting method : no algorithm "
                "for method \"%s\" (%s)\n",ssh_kex_nums[algo],list);
        return -1;
    }
    if(opt->wanted_methods[algo])
        free(opt->wanted_methods[algo]);
    opt->wanted_methods[algo]=strdup(list);    
    return 0;
}

static char *get_username_from_uid(int uid){
    struct passwd *pwd;
    char *user;
    while((pwd=getpwent())){
        if(pwd->pw_uid == uid){
            user=strdup(pwd->pw_name);
            endpwent();
            return user;
        }
    }
    endpwent();
    ssh_set_error(NULL,SSH_FATAL,"uid %d doesn't exist !",uid);
    return NULL;
}

/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(SSH_OPTIONS *opt){
    char *user;
    if(opt->username)
        return 0;
    user=getenv("USER");
    if(user){
        opt->username=strdup(user);
        return 0;
    }
    user=get_username_from_uid(getuid());
    if(user){
        opt->username=user;
        return 0;
    }
    return -1;
}

int ssh_options_default_ssh_dir(SSH_OPTIONS *opt){
    char buffer[256];
    if(opt->ssh_dir)
        return 0;
    snprintf(buffer,256,"%s/.ssh/",ssh_get_user_home_dir());
    opt->ssh_dir=strdup(buffer);
    return 0;
}

int ssh_options_default_known_hosts_file(SSH_OPTIONS *opt){
    char buffer[1024];
    if(opt->known_hosts_file)
        return 0;
    ssh_options_default_ssh_dir(opt);
    snprintf(buffer,1024,"%s/known_hosts",opt->ssh_dir);
    opt->known_hosts_file=strdup(buffer);
    return 0;
}

/** During ssh_connect(), libssh will call the callback with status from
 * 0.0 to 1.0
 * \brief set a callback to show connection status in realtime
 * \param opt options structure
 * \param callback a function pointer to a callback in form f(void *userarg, float status)
 * \param arg value to be given as argument to the callback function when it is called
 * \see ssh_connect()
 */
void ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)(void *arg, float status), void *arg ){
    opt->connect_status_function=callback;
    opt->connect_status_arg=arg;
}

/** \bug currently it only timeouts the socket connection, not the
 * complete exchange
 * \brief set a timeout for the connection
 * \param opt options structure
 * \param seconds number of seconds
 * \param usec number of micro seconds
 */
void ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds,long usec){
    opt->timeout=seconds;
    opt->timeout_usec=usec;
}

/** Default value is 0 (no connection to SSH1 servers) 
 * \brief allow or deny the connection to SSH1 servers
 * \param opt options structure
 * \param allow nonzero values allow ssh1
 */
void ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow){
    if(allow)
        opt->ssh1allowed=1;
    else
        opt->ssh1allowed=0;
}

/** Default value is 1 (allow connection to SSH2 servers)
 * \brief allow or deny the connection to SSH2 servers
 * \param opt options structure
 * \param allow nonzero values allow ssh2
 */
void ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow){
    if(allow)
        opt->ssh2allowed=1;
    else
        opt->ssh2allowed=0;
}

/**
 * This is a helper for your application to generate the appropriate
 * options from the command line arguments.\n
 * the argv array and argc value are changed so that parsed
 * arguments won't appear anymore in them.\n
 * The single arguments (without switches) are not parsed. thus,
 * myssh -u aris localhost \n
 * command won't set the hostname value of options to localhost.
 * \brief parse command line arguments
 * \param options an empty option structure pointer
 * \param argcptr pointer to argument count
 * \param argv arguments list pointer
 * \returns 0 on success, -1 on error
 * \sa ssh_options_new()
 */
int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv){
    int i;
    int argc=*argcptr;
    char *user=NULL;
    int port=22;
    int debuglevel=0;
    int usersa=0;
    int usedss=0;
    int compress=0;
    int cont=1;
    char *cipher=NULL;
    char *localaddr=NULL;
    char *identity=NULL;
    char **save=malloc(argc * sizeof(char *));
    int current=0;
#ifdef HAVE_SSH1
    int ssh1=1;
#else
    int ssh1=0;
#endif
    int ssh2=1;
    
    int saveoptind=optind; /* need to save 'em */
    int saveopterr=opterr;
    opterr=0; /* shut up getopt */
    while(cont && ((i=getopt(argc,argv,"c:i:Cl:p:vb:rd12"))!=-1)){

        switch(i){
            case 'l':
                user=optarg;
                break;
            case 'p':
                port=atoi(optarg)&0xffff;
                break;
            case 'v':
                debuglevel++;
                break;
            case 'r':
                usersa++;
                break;
            case 'd':
                usedss++;
                break;
            case 'c':
                cipher=optarg;
                break;
            case 'i':
                identity=optarg;
                break;
            case 'b':
                localaddr=optarg;
                break;
            case 'C':
                compress++;
                break;
            case '2':
                ssh2=1;
                ssh1=0;
                break;
            case '1':
                ssh2=0;
                ssh1=1;
                break;
            default:
                {
                char opt[3]="- ";
                opt[1]=optopt;
                save[current++]=strdup(opt);
                if(optarg)
                    save[current++]=argv[optind+1];
            }
        }
    }
    opterr=saveopterr;
    while(optind < argc)
        save[current++]=argv[optind++];
        
    if(usersa && usedss){
        ssh_set_error(NULL,SSH_FATAL,"either RSA or DSS must be chosen");
        cont=0;
    }
    ssh_set_verbosity(debuglevel);
    optind=saveoptind;
    if(!cont){
        free(save);
        return -1;
    }
    /* first recopy the save vector into original's */
    for(i=0;i<current;i++)
        argv[i+1]=save[i]; // don't erase argv[0]
    argv[current+1]=NULL;
    *argcptr=current+1;
    free(save);
    /* set a new option struct */
    if(compress){
        if(ssh_options_set_wanted_algos(options,SSH_COMP_C_S,"zlib"))
            cont=0;
        if(ssh_options_set_wanted_algos(options,SSH_COMP_S_C,"zlib"))
            cont=0;
    }
    if(cont &&cipher){
        if(ssh_options_set_wanted_algos(options,SSH_CRYPT_C_S,cipher))
            cont=0;
        if(cont && ssh_options_set_wanted_algos(options,SSH_CRYPT_S_C,cipher))
            cont=0;
    }
    if(cont && usersa)
        if(ssh_options_set_wanted_algos(options,SSH_HOSTKEYS,"ssh-rsa"))
            cont=0;
    if(cont && usedss)
        if(ssh_options_set_wanted_algos(options,SSH_HOSTKEYS,"ssh-dss"))
            cont=0;
    if(cont && user)
        ssh_options_set_username(options,user);
    if(cont && identity)
        ssh_options_set_identity(options,identity);
    if(cont && localaddr)
        ssh_options_set_bind(options,localaddr,0);
    ssh_options_set_port(options,port);
    //options->bindport=port;
    ssh_options_allow_ssh1(options,ssh1);
    ssh_options_allow_ssh2(options,ssh2);
        
    if(!cont){
        return -1;
    } else
        return 0 ;   
}



/** @} */
