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
 * The C++ bindings for libssh are completely embedded in a single .hpp file, and
 * this for two reasons:
 * - C++ is hard to keep binary compatible, C is easy. We try to keep libssh C version
 *   as much as possible binary compatible between releases, while this would be hard for
 *   C++. If you compile your program with these headers, you will only link to the C version
 *   of libssh which will be kept ABI compatible. No need to recompile your C++ program
 *   each time a new binary-compatible version of libssh is out
 * - Most of the functions in this file are really short and are probably worth the "inline"
 *   linking mode, which the compiler can decide to do in some case. There would be nearly no
 *   performance penalty of using the wrapper rather than native calls.
 */

#include <libssh/libssh.h>
namespace ssh {

/** @brief This class describes a SSH Exception object. This object can be throwed
 * by several SSH functions that interact with the network, and may fail because of
 * socket, protocol or memory errors.
 */
class SshException{
public:
  SshException(ssh_session csession){
    code=ssh_get_error_code(csession);
    description=ssh_get_error(csession);
  }
  SshException(const SshException &e){
    code=e.code;
    description=e.description;
  }
  /** @brief returns the Error code
   * @returns SSH_FATAL Fatal error happened (not recoverable)
   * @returns SSH_REQUEST_DENIED Request was denied by remote host
   * @see ssh_get_error_code
   */
  int getCode(){
    return code;
  }
  /** @brief returns the error message of the last exception
   * @returns pointer to a c string containing the description of error
   * @see ssh_get_error
   */
  const char *getError(){
    return description;
  }
private:
  int code;
  const char *description;
};

/**
 * The ssh::Session class contains the state of a SSH connection.
 */
class Session {
  friend class Channel;
public:
  Session(){
    c_session=ssh_new();
  }
  ~Session(){
    ssh_free(c_session);
    c_session=NULL;
  }
  void setOption(enum ssh_options_e type, const char *option){
    ssh_options_set(c_session,type,option);
  }
  void setOption(enum ssh_options_e type, long int option){
    ssh_options_set(c_session,type,&option);
  }
  void setOption(enum ssh_options_e type, void *option){
    ssh_options_set(c_session,type,option);
  }
  /** @brief connects to the remote host
   * @throws SshException on error
   * @see ssh_connect
   */
  void connect(){
    int ret=ssh_connect(c_session);
    if(ret != SSH_OK){
      throw SshException(getCSession());
    }
  }
  int userauthAutopubkey(){
    return ssh_userauth_autopubkey(c_session,NULL);
  }
  int userauthNone();
  int userauthPassword(const char *password);
  int userauthOfferPubkey(ssh_string pubkey);
  int userauthPubkey(ssh_string pubkey, ssh_private_key privkey);
  int userauthPubkey(ssh_private_key privkey);
  int userauthPrivatekeyFile(const char *filename, const char *passphrase);
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
  void log(int priority, const char *format, ...);
  void optionsCopy(const Session &source);
  void optionsParseConfig(const char *file);
  void silentDisconnect();
  int writeKnownhost();
private:
  ssh_session c_session;
  ssh_session getCSession(){
    return c_session;
  }
};

class Channel {
public:
  Channel(Session &session){
    channel=channel_new(session.getCSession());
    this->session=&session;
  }
  ~Channel(){
    channel_free(channel);
    channel=NULL;
  }
  int acceptX11(int timeout_ms);
  int changePtySize(int cols, int rows);
  int acceptForward(int timeout_ms);
  int close();
  int cancelForward(const char *address, int port);
  int listenForward(const char *address, int port, int &boundport);
  int getExitStatus();
  Session &getSession(){
    return *session;
  }
  int isClosed();
  int isEof();
  int isOpen();
  int openForward(const char *remotehost, int remoteport,
      const char *sourcehost=NULL, int localport=0);
  int openSession();
  int poll(bool is_stderr=false);
  int read(void *dest, size_t count, bool is_stderr=false);
  int readNonblocking(void *dest, size_t count, bool is_stderr=false);
  int requestEnv(const char *name, const char *value);
  int requestExec(const char *cmd);
  int requestPty(const char *term=NULL, int cols=0, int rows=0);
  int requestShell();
  int requestSendSignal(const char *signum);
  int requestSubsystem(const char *subsystem);
  int requestX11(bool single_connection, const char *protocol, const char *cookie,
      int screen_number);
  int sendEof();
  int write(const void *data, size_t len, bool is_stderr=false);
private:
  Session *session;
  ssh_channel channel;
};

} // namespace ssh
/** @}
 */
#endif /* LIBSSHPP_HPP_ */
