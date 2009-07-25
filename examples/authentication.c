/*
 * authentication.c
 * This file contains an example of how to do an authentication to a
 * SSH server using libssh
 */

/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>
#include "examples_common.h"

int authenticate_kbdint(ssh_session session){
  int err=ssh_userauth_kbdint(session,NULL,NULL);
  const char *name, *instruction, *prompt;
  char *ptr;
  char buffer[128];
  int i,n;
  char echo;
  while (err==SSH_AUTH_INFO){
    name=ssh_userauth_kbdint_getname(session);
    instruction=ssh_userauth_kbdint_getinstruction(session);
    n=ssh_userauth_kbdint_getnprompts(session);
    if(strlen(name)>0)
      printf("%s\n",name);
    if(strlen(instruction)>0)
      printf("%s\n",instruction);
    for(i=0;i<n;++i){
      prompt=ssh_userauth_kbdint_getprompt(session,i,&echo);
      if(echo){
        printf("%s",prompt);
        fgets(buffer,sizeof(buffer),stdin);
        buffer[sizeof(buffer)-1]=0;
        if((ptr=strchr(buffer,'\n')))
          *ptr=0;
        if (ssh_userauth_kbdint_setanswer(session,i,buffer) < 0) {
          return SSH_AUTH_ERROR;
        }
        memset(buffer,0,strlen(buffer));
      } else {
        ptr=getpass(prompt);
        if (ssh_userauth_kbdint_setanswer(session,i,ptr) < 0) {
          return SSH_AUTH_ERROR;
        }
      }
    }
    err=ssh_userauth_kbdint(session,NULL,NULL);
  }
  return err;
}

int authenticate_console(ssh_session session){
  int auth;
  int methods;
  char *password;
  char *banner;

  ssh_userauth_none(session, NULL);
  methods = ssh_auth_list(session);
  printf("supported auth methods: ");
  if (methods & SSH_AUTH_METHOD_PUBLICKEY) {
    printf("publickey");
  }
  if (methods & SSH_AUTH_METHOD_INTERACTIVE) {
    printf(", keyboard-interactive");
  }
  if (methods & SSH_AUTH_METHOD_PASSWORD) {
    printf(", password");
  }
  printf("\n");

  auth=ssh_userauth_autopubkey(session, NULL);
  if(auth==SSH_AUTH_ERROR){
    return auth;
  }
  banner=ssh_get_issue_banner(session);
  if(banner){
    printf("%s\n",banner);
    free(banner);
  }
  if(auth!=SSH_AUTH_SUCCESS && (methods & SSH_AUTH_METHOD_INTERACTIVE)){
    auth=authenticate_kbdint(session);
    if(auth==SSH_AUTH_ERROR){
      return auth;
    }
  }
  if(auth!=SSH_AUTH_SUCCESS && (methods & SSH_AUTH_METHOD_PASSWORD)){
    password=getpass("Password: ");
    if(ssh_userauth_password(session,NULL,password) != SSH_AUTH_SUCCESS){
      return auth;
    }
    memset(password,0,strlen(password));
  }
  if(auth==SSH_AUTH_SUCCESS)
    ssh_log(session, SSH_LOG_FUNCTIONS, "Authentication success");
  if(auth==SSH_AUTH_PARTIAL)
    return SSH_AUTH_DENIED;
  return auth;
}
