/*
 * scp - SSH scp wrapper functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis <aris@0xbadc0de.be>
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
 */

#include "libssh/priv.h"
#include <string.h>

/** @brief Creates a new scp session
 * @param session the SSH session to use
 * @param mode one of SSH_SCP_WRITE or SSH_SCP_READ, depending if you need to drop files remotely or read them.
 * It is not possible to combine read and write.
 * @returns NULL if the creation was impossible.
 * @returns a ssh_scp handle if it worked.
 */
ssh_scp ssh_scp_new(ssh_session session, int mode, const char *location){
  ssh_scp scp=malloc(sizeof(struct ssh_scp_struct));
  if(scp == NULL){
    ssh_set_error(session,SSH_FATAL,"Error allocating memory for ssh_scp");
    return NULL;
  }
  ZERO_STRUCTP(scp);
  if(mode != SSH_SCP_WRITE && mode != SSH_SCP_READ){
    ssh_set_error(session,SSH_FATAL,"Invalid mode %d for ssh_scp_new()",mode);
    ssh_scp_free(scp);
    return NULL;
  }
  scp->session=session;
  scp->mode=mode;
  scp->location=strdup(location);
  scp->channel=NULL;
  return scp;
}

int ssh_scp_init(ssh_scp scp){
  int r;
  char execbuffer[1024];
  u_int8_t code;
  scp->channel=channel_new(scp->session);
  if(scp->channel == NULL)
    return SSH_ERROR;
  r= channel_open_session(scp->channel);
  if(r==SSH_ERROR){
    return SSH_ERROR;
  }
  if(scp->mode == SSH_SCP_WRITE)
    snprintf(execbuffer,sizeof(execbuffer),"scp -t %s",scp->location);
  else
    snprintf(execbuffer,sizeof(execbuffer),"scp -f %s",scp->location);
  if(channel_request_exec(scp->channel,execbuffer) == SSH_ERROR){
    return SSH_ERROR;
  }
  r=channel_read(scp->channel,&code,1,0);
  if(code != 0){
    ssh_set_error(scp->session,SSH_FATAL, "scp status code %ud not valid", code);
    return SSH_ERROR;
  }
  return SSH_OK;
}

int ssh_scp_close(ssh_scp scp){
  if(channel_send_eof(scp->channel) == SSH_ERROR)
    return SSH_ERROR;
  if(channel_close(scp->channel) == SSH_ERROR)
    return SSH_ERROR;
  channel_free(scp->channel);
  scp->channel=NULL;
  return SSH_OK;
}

void ssh_scp_free(ssh_scp scp){
  if(scp->channel)
    channel_free(scp->channel);
  SAFE_FREE(scp->location);
  SAFE_FREE(scp);
}

/** @brief initializes the sending of a file to a scp in sink mode
 * @param filename Name of the file being sent. It should not contain any path indicator
 * @param size Exact size in bytes of the file being sent.
 * @param perms Text form of the unix permissions for the new file, e.g. "0644"
 * @returns SSH_OK if the file is ready to be sent.
 * @returns SSH_ERROR if an error happened.
 */
int ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, const char *perms){
  char buffer[1024];
  int r;
  u_int8_t code;
  snprintf(buffer,sizeof(buffer),"C%s %ld %s\n",perms, size, filename);
  r=channel_write(scp->channel,buffer,strlen(buffer));
  if(r==SSH_ERROR)
    return SSH_ERROR;
  r=channel_read(scp->channel,&code,1,0);
  if(code != 0){
    ssh_set_error(scp->session,SSH_FATAL, "scp status code %ud not valid", code);
    return SSH_ERROR;
  }
  scp->filelen = size;
  scp->processed = 0;
  return SSH_OK;
}

/** @brief Write into a remote scp file
 * @param buffer the buffer to write
 * @param len the number of bytes to write
 * @returns SSH_OK the write was successful
 * @returns SSH_ERROR an error happened while writing
 */
int ssh_scp_write(ssh_scp scp, const void *buffer, size_t len){
  int w,r;
  u_int8_t code;
  if(scp->processed + len > scp->filelen)
    len = scp->filelen - scp->processed;
  w=channel_write(scp->channel,buffer,len);
  if(w != SSH_ERROR)
    scp->processed += w;
  else
    return w;
  if(scp->processed == scp->filelen) {
    r=channel_read(scp->channel,&code,1,0);
    if(code != 0){
      ssh_set_error(scp->session,SSH_FATAL, "scp status code %ud not valid", code);
      return SSH_ERROR;
    }
    scp->processed=scp->filelen=0;
  }
  return SSH_OK;
}
