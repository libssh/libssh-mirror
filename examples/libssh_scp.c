/* libssh_scp.c
 * Sample implementation of a SCP client
 */

/*
Copyright 2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is 
allowed to cut-and-paste working code from this file to any license of
program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libssh/libssh.h>
#include "examples_common.h"

char *host;
char *user;
int sftp;

static void usage(const char *argv0){
  fprintf(stderr,"Usage : %s [options] [login@]hostname\n"
      "sample scp client - libssh-%s\n"
      "Options :\n"
      "  -l user : log in as user\n"
      "  -p port : connect to port\n"
      "  -d : use DSS to verify host public key\n"
      "  -r : use RSA to verify host public key\n",
      argv0,
      ssh_version(0));
  exit(0);
}

static int opts(int argc, char **argv){
  int i;
  if(strstr(argv[0],"sftp"))
    sftp=1;
  //    for(i=0;i<argc;i++)
  //        printf("%d : %s\n",i,argv[i]);
  /* insert your own arguments here */
  while((i=getopt(argc,argv,""))!=-1){
    switch(i){
      default:
        fprintf(stderr,"unknown option %c\n",optopt);
        usage(argv[0]);
    }
  }
  if(optind < argc)
    host=argv[optind++];
  if(host==NULL)
    usage(argv[0]);
  return 0;
}

ssh_channel chan;

static void select_loop(SSH_SESSION *session,ssh_channel channel){
  fd_set fds;
  struct timeval timeout;
  char buffer[10];
  ssh_buffer readbuf=buffer_new();
  ssh_channel channels[2];
  int lus;
  int eof=0;
  int maxfd;
  int ret;
  while(channel){
    /* when a signal is caught, ssh_select will return
     * with SSH_EINTR, which means it should be started
     * again. It lets you handle the signal the faster you
     * can, like in this window changed example. Of course, if
     * your signal handler doesn't call libssh at all, you're
     * free to handle signals directly in sighandler.
     */
    do{
      FD_ZERO(&fds);
      if(!eof)
        FD_SET(0,&fds);
      timeout.tv_sec=30;
      timeout.tv_usec=0;
      FD_SET(ssh_get_fd(session),&fds);
      maxfd=ssh_get_fd(session)+1;
      ret=select(maxfd,&fds,NULL,NULL,&timeout);
      if(ret==EINTR)
        continue;
      if(FD_ISSET(0,&fds)){
        lus=read(0,buffer,10);
        if(lus)
          channel_write(channel,buffer,lus);
        else {
          eof=1;
          channel_send_eof(channel);
        }
      }
      if(FD_ISSET(ssh_get_fd(session),&fds)){
        ssh_set_fd_toread(session);
      }
      channels[0]=channel; // set the first channel we want to read from
      channels[1]=NULL;
      ret=channel_select(channels,NULL,NULL,NULL); // no specific timeout - just poll
    } while (ret==EINTR || ret==SSH_EINTR);

    // we already looked for input from stdin. Now, we are looking for input from the channel

    if(channel && channel_is_closed(channel)){
      ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",channel_get_exit_status(channel));

      channel_free(channel);
      channel=NULL;
      channels[0]=NULL;
    }
    if(channels[0]){
      while(channel && channel_is_open(channel) && channel_poll(channel,0)){
        lus=channel_read_buffer(channel,readbuf,0,0);
        if(lus==-1){
          fprintf(stderr, "Error reading channel: %s\n",
              ssh_get_error(session));
          return;
        }
        if(lus==0){
          ssh_log(session,SSH_LOG_RARE,"EOF received\n");
          ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",channel_get_exit_status(channel));

          channel_free(channel);
          channel=channels[0]=NULL;
        } else
          write(1,buffer_get(readbuf),lus);
      }
      while(channel && channel_is_open(channel) && channel_poll(channel,1)){ /* stderr */
        lus=channel_read_buffer(channel,readbuf,0,1);
        if(lus==-1){
          fprintf(stderr, "Error reading channel: %s\n",
              ssh_get_error(session));
          return;
        }
        if(lus==0){
          ssh_log(session,SSH_LOG_RARE,"EOF received\n");
          ssh_log(session,SSH_LOG_RARE,"exit-status : %d\n",channel_get_exit_status(channel));
          channel_free(channel);
          channel=channels[0]=NULL;
        } else
          write(2,buffer_get(readbuf),lus);
      }
    }
    if(channel && channel_is_closed(channel)){
      channel_free(channel);
      channel=NULL;
    }
  }
  buffer_free(readbuf);
}

static void batch_shell(ssh_session session){
  ssh_channel channel;
  char buffer[1024];
  channel=channel_new(session);
  channel_open_session(channel);
  if(channel_request_exec(channel,buffer)){
    printf("error executing \"%s\" : %s\n",buffer,ssh_get_error(session));
    return;
  }
  select_loop(session,channel);
}

int main(int argc, char **argv){
  SSH_SESSION *session;
  SSH_OPTIONS *options;
  int auth=0;


  options=ssh_options_new();
  if(ssh_options_getopt(options,&argc, argv)){
    fprintf(stderr,"error parsing command line :%s\n",ssh_get_error(options));
    usage(argv[0]);
  }
  opts(argc,argv);
  if (user) {
    if (ssh_options_set_username(options,user) < 0) {
      ssh_options_free(options);
      return 1;
    }
  }

  if (ssh_options_set_host(options,host) < 0) {
    ssh_options_free(options);
    return 1;
  }
  session=ssh_new();
  ssh_set_options(session,options);
  if(ssh_connect(session)){
    fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
    ssh_disconnect(session);
    ssh_finalize();
    return 1;
  }
  if(verify_knownhost(session)<0){
    ssh_disconnect(session);
    ssh_finalize();
    return 1;
  }
  auth=authenticate_console(session);
  if(auth==SSH_AUTH_SUCCESS){
    batch_shell(session);
  } else if(auth==SSH_AUTH_DENIED){
    fprintf(stderr,"Authentication failed\n");
  } else {
    fprintf(stderr,"Error while authenticating : %s\n",ssh_get_error(session));
  }
  ssh_disconnect(session);
  ssh_finalize();

  return 0;
}
