/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#ifndef LIBSSHPP_HPP_
#define LIBSSHPP_HPP_

/** @defgroup ssh_cpp libssh C++ wrapper
 * @addtogroup ssh_cpp
 * @{
 */

#include <libssh/libssh.h>

namespace ssh {
class Session {
public:
  Session(){
    session=ssh_new();
  }
  ~Session(){
    ssh_free(session);
    session=NULL;
  }
  void setOption(enum ssh_options_e type, const char *option){
    ssh_options_set(session,type,option);
  }
  void setOption(enum ssh_options_e type, long int option){
    ssh_options_set(session,type,&option);
  }
  void setOption(enum ssh_options_e type, void *option){
    ssh_options_set(session,type,option);
  }
  int connect(){
    return ssh_connect(session);
  }
  int userauthAutopubkey(){
    return ssh_userauth_autopubkey(session,NULL);
  }
  int getAuthList();
  int disconnect();
  const char *getDisconnectMessage();
  const char *getError();
  int getErrorCode();
  socket_t getSocket();
  const char *getIssueBanner();
  int getOpensshVersion();
  int getVersion();
  int isServerKnown();

private:
  ssh_session session;
};
}


/** @}
 */
#endif /* LIBSSHPP_HPP_ */
