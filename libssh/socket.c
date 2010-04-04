/*
 * socket.c - socket functions for the library
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008,2009      by Aris Adamantiadis
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include "libssh/priv.h"
#include "libssh/callbacks.h"
#include "libssh/socket.h"
#include "libssh/buffer.h"
#include "libssh/poll.h"
#include "libssh/session.h"

/**
 * @internal
 *
 * @defgroup libssh_socket The SSH socket functions.
 * @ingroup libssh
 *
 * Functions for handling sockets.
 *
 * @{
 */

enum ssh_socket_states_e {
	SSH_SOCKET_NONE,
	SSH_SOCKET_CONNECTING,
	SSH_SOCKET_CONNECTED,
	SSH_SOCKET_EOF,
	SSH_SOCKET_ERROR,
	SSH_SOCKET_CLOSED
};

struct ssh_socket_struct {
  socket_t fd;
  int last_errno;
  int data_to_read; /* reading now on socket will
                       not block */
  int data_to_write;
  int data_except;
  enum ssh_socket_states_e state;
  ssh_buffer out_buffer;
  ssh_buffer in_buffer;
  ssh_session session;
  ssh_socket_callbacks callbacks;
  ssh_poll_handle poll;
};

static int ssh_socket_unbuffered_read(ssh_socket s, void *buffer, uint32_t len);
static int ssh_socket_unbuffered_write(ssh_socket s, const void *buffer,
		uint32_t len);

/**
 * \internal
 * \brief inits the socket system (windows specific)
 */
int ssh_socket_init(void) {
#ifdef _WIN32
  struct WSAData wsaData;

  /* Initiates use of the Winsock DLL by a process. */
  if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
    return -1;
  }
#endif
  return 0;
}
/**
 * \internal
 * \brief creates a new Socket object
 */
ssh_socket ssh_socket_new(ssh_session session) {
  ssh_socket s;

  s = malloc(sizeof(struct ssh_socket_struct));
  if (s == NULL) {
    return NULL;
  }
  s->fd = -1;
  s->last_errno = -1;
  s->session = session;
  s->in_buffer = buffer_new();
  if (s->in_buffer == NULL) {
    SAFE_FREE(s);
    return NULL;
  }
  s->out_buffer=buffer_new();
  if (s->out_buffer == NULL) {
    buffer_free(s->in_buffer);
    SAFE_FREE(s);
    return NULL;
  }
  s->data_to_read = 0;
  s->data_to_write = 0;
  s->data_except = 0;
  s->poll=NULL;
  s->state=SSH_SOCKET_NONE;
  return s;
}

/**
 * @internal
 * @brief the socket callbacks, i.e. callbacks to be called
 * upon a socket event.
 * @param s socket to set callbacks on.
 * @param callbacks a ssh_socket_callback object reference.
 */

void ssh_socket_set_callbacks(ssh_socket s, ssh_socket_callbacks callbacks){
	s->callbacks=callbacks;
}

int ssh_socket_pollcallback(ssh_poll_handle p, socket_t fd, int revents, void *v_s){
	ssh_socket s=(ssh_socket )v_s;
	char buffer[4096];
	int r,w;
	int err=0;
	socklen_t errlen=sizeof(err);
	if(revents & POLLERR){
		/* Check if we are in a connecting state */
		if(s->state==SSH_SOCKET_CONNECTING){
			s->state=SSH_SOCKET_ERROR;
			ssh_poll_free(p);
			s->poll=p=NULL;
			getsockopt(fd,SOL_SOCKET,SO_ERROR,(void *)&err,&errlen);
			s->last_errno=err;
#ifdef _WIN32
			closesocket(fd);
#else
			close(fd);
#endif
			s->fd=-1;
			if(s->callbacks && s->callbacks->connected)
				s->callbacks->connected(SSH_SOCKET_CONNECTED_ERROR,err,
						s->callbacks->userdata);
			return 0;
		}
		/* Then we are in a more standard kind of error */
		/* force a read to get an explanation */
		revents |= POLLIN;
	}
	if(revents & POLLIN){
		s->data_to_read=1;
		r=ssh_socket_unbuffered_read(s,buffer,sizeof(buffer));
		if(r<0){
			if(p != NULL)
				ssh_poll_set_events(p,ssh_poll_get_events(p) & ~POLLIN);
			if(s->callbacks && s->callbacks->exception){
				s->callbacks->exception(
						SSH_SOCKET_EXCEPTION_ERROR,
						s->last_errno,s->callbacks->userdata);
			}
		}
		if(r==0){
			ssh_poll_set_events(p,ssh_poll_get_events(p) & ~POLLIN);
			if(s->callbacks && s->callbacks->exception){
				s->callbacks->exception(
						SSH_SOCKET_EXCEPTION_EOF,
						0,s->callbacks->userdata);
			}
		}
		if(r>0){
			/* Bufferize the data and then call the callback */
			buffer_add_data(s->in_buffer,buffer,r);
			if(s->callbacks && s->callbacks->data){
				r= s->callbacks->data(buffer_get_rest(s->in_buffer),
						buffer_get_rest_len(s->in_buffer),
						s->callbacks->userdata);
				buffer_pass_bytes(s->in_buffer,r);
			}
		}
	}
#ifdef _WIN32
	if(revents & POLLOUT || revents & POLLWRNORM){
#else
	if(revents & POLLOUT){
#endif
		/* First, POLLOUT is a sign we may be connected */
		if(s->state == SSH_SOCKET_CONNECTING){
			ssh_log(s->session,SSH_LOG_PACKET,"Received POLLOUT in connecting state");
			s->state = SSH_SOCKET_CONNECTED;
			ssh_poll_set_events(p,POLLOUT | POLLIN | POLLERR);
			ssh_sock_set_blocking(ssh_socket_get_fd(s));
			if(s->callbacks && s->callbacks->connected)
				s->callbacks->connected(SSH_SOCKET_CONNECTED_OK,0,s->callbacks->userdata);
			return 0;
		}
		/* So, we can write data */
		s->data_to_write=1;
		/* If buffered data is pending, write it */
		if(buffer_get_rest_len(s->out_buffer) > 0){
			w=ssh_socket_unbuffered_write(s, buffer_get_rest(s->out_buffer),
		          buffer_get_rest_len(s->out_buffer));
			if(w>0)
				buffer_pass_bytes(s->out_buffer,w);
		} else if(s->callbacks && s->callbacks->controlflow){
			/* Otherwise advertise the upper level that write can be done */
			s->callbacks->controlflow(SSH_SOCKET_FLOW_WRITEWONTBLOCK,s->callbacks->userdata);
		}
		ssh_poll_remove_events(p,POLLOUT);
			/* TODO: Find a way to put back POLLOUT when buffering occurs */
	}
	return 0;
}

void ssh_socket_register_pollcallback(ssh_socket s, ssh_poll_handle p){
	ssh_poll_set_callback(p,ssh_socket_pollcallback,s);
	s->poll=p;
}

/** @internal
 * @brief returns the poll handle corresponding to the socket,
 * creates it if it does not exist.
 * @returns allocated and initialized ssh_poll_handle object
 */
ssh_poll_handle ssh_socket_get_poll_handle(ssh_socket s){
	if(s->poll)
		return s->poll;
	s->poll=ssh_poll_new(s->fd,0,ssh_socket_pollcallback,s);
	return s->poll;
}

/** \internal
 * \brief Deletes a socket object
 */
void ssh_socket_free(ssh_socket s){
  if (s == NULL) {
    return;
  }
  ssh_socket_close(s);
  buffer_free(s->in_buffer);
  buffer_free(s->out_buffer);
  if(s->poll)
  	ssh_poll_free(s->poll);
  SAFE_FREE(s);
}

#ifndef _WIN32
int ssh_socket_unix(ssh_socket s, const char *path) {
  struct sockaddr_un sunaddr;

  sunaddr.sun_family = AF_UNIX;
  snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path), "%s", path);

  s->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s->fd < 0) {
    return -1;
  }

  if (fcntl(s->fd, F_SETFD, 1) == -1) {
    close(s->fd);
    s->fd = -1;
    return -1;
  }

  if (connect(s->fd, (struct sockaddr *) &sunaddr,
        sizeof(sunaddr)) < 0) {
    close(s->fd);
    s->fd = -1;
    return -1;
  }

  return 0;
}
#endif

/** \internal
 * \brief closes a socket
 */
void ssh_socket_close(ssh_socket s){
  if (ssh_socket_is_open(s)) {
#ifdef _WIN32
    closesocket(s->fd);
    s->last_errno = WSAGetLastError();
#else
    close(s->fd);
    s->last_errno = errno;
#endif
    s->fd=-1;
  }
}

/** \internal
 * \brief sets the file descriptor of the socket
 */
void ssh_socket_set_fd(ssh_socket s, socket_t fd) {
  s->fd = fd;
  if(s->poll)
  	ssh_poll_set_fd(s->poll,fd);
}

/** \internal
 * \brief returns the file descriptor of the socket
 */
socket_t ssh_socket_get_fd(ssh_socket s) {
  return s->fd;
}

/** \internal
 * \brief returns nonzero if the socket is open
 */
int ssh_socket_is_open(ssh_socket s) {
  return s->fd != -1;
}

/** \internal
 * \brief read len bytes from socket into buffer
 */
static int ssh_socket_unbuffered_read(ssh_socket s, void *buffer, uint32_t len) {
  int rc = -1;

  if (s->data_except) {
    return -1;
  }

  rc = recv(s->fd,buffer, len, 0);
#ifdef _WIN32
  s->last_errno = WSAGetLastError();
#else
  s->last_errno = errno;
#endif
  s->data_to_read = 0;

  if (rc < 0) {
    s->data_except = 1;
  }

  return rc;
}

/** \internal
 * \brief writes len bytes from buffer to socket
 */
static int ssh_socket_unbuffered_write(ssh_socket s, const void *buffer,
    uint32_t len) {
  int w = -1;

  if (s->data_except) {
    return -1;
  }

  w = send(s->fd,buffer, len, 0);
#ifdef _WIN32
  s->last_errno = WSAGetLastError();
#else
  s->last_errno = errno;
#endif
  s->data_to_write = 0;
  /* Reactive the POLLOUT detector in the poll multiplexer system */
  if(s->poll){
  	ssh_poll_set_events(s->poll,ssh_poll_get_events(s->poll) | POLLOUT);
  }
  if (w < 0) {
    s->data_except = 1;
  }

  return w;
}

/** \internal
 * \brief returns nonzero if the current socket is in the fd_set
 */
int ssh_socket_fd_isset(ssh_socket s, fd_set *set) {
  if(s->fd == -1) {
    return 0;
  }
  return FD_ISSET(s->fd,set);
}

/** \internal
 * \brief sets the current fd in a fd_set and updates the fd_max
 */

void ssh_socket_fd_set(ssh_socket s, fd_set *set, int *fd_max) {
  if (s->fd == -1)
    return;
  FD_SET(s->fd,set);
  if (s->fd >= *fd_max) {
    *fd_max = s->fd + 1;
  }
}

/** \internal
 * \brief reads blocking until len bytes have been read
 */
int ssh_socket_completeread(ssh_socket s, void *buffer, uint32_t len) {
  int r = -1;
  uint32_t total = 0;
  uint32_t toread = len;
  if(! ssh_socket_is_open(s)) {
    return SSH_ERROR;
  }

  while((r = ssh_socket_unbuffered_read(s, ((uint8_t*)buffer + total), toread))) {
    if (r < 0) {
      return SSH_ERROR;
    }
    total += r;
    toread -= r;
    if (total == len) {
      return len;
    }
    if (r == 0) {
      return 0;
    }
  }

  /* connection closed */
  return total;
}

/** \internal
 * \brief Blocking write of len bytes
 */
int ssh_socket_completewrite(ssh_socket s, const void *buffer, uint32_t len) {
  ssh_session session = s->session;
  int written = -1;

  enter_function();

  if(! ssh_socket_is_open(s)) {
    leave_function();
    return SSH_ERROR;
  }

  while (len >0) {
    written = ssh_socket_unbuffered_write(s, buffer, len);
    if (written == 0 || written == -1) {
      leave_function();
      return SSH_ERROR;
    }
    len -= written;
    buffer = ((uint8_t*)buffer +  written);
  }

  leave_function();
  return SSH_OK;
}

/** \internal
 * \brief buffered read of data (complete)
 * \returns SSH_OK or SSH_ERROR.
 * \returns SSH_AGAIN in nonblocking mode
 */
int ssh_socket_read(ssh_socket s, void *buffer, int len){
  ssh_session session = s->session;
  int rc = SSH_ERROR;

  enter_function();

  rc = ssh_socket_wait_for_data(s, s->session, len);
  if (rc != SSH_OK) {
    leave_function();
    return rc;
  }

  memcpy(buffer, buffer_get_rest(s->in_buffer), len);
  buffer_pass_bytes(s->in_buffer, len);

  leave_function();
  return SSH_OK;
}

/** \internal
 * \brief buffered write of data
 * \returns SSH_OK, or SSH_ERROR
 * \warning has no effect on socket before a flush
 */
int ssh_socket_write(ssh_socket s, const void *buffer, int len) {
  ssh_session session = s->session;
  enter_function();
  if (buffer_add_data(s->out_buffer, buffer, len) < 0) {
    return SSH_ERROR;
  }
  leave_function();
  return len;
}


/** \internal
 * \brief wait for data on socket
 * \param s socket
 * \param session the ssh session
 * \param len number of bytes to be read
 * \returns SSH_OK bytes are available on socket
 * \returns SSH_AGAIN need to call later for data
 * \returns SSH_ERROR error happened
 */
int ssh_socket_wait_for_data(ssh_socket s, ssh_session session, uint32_t len) {
  char buffer[4096] = {0};
  char *buf = NULL;
  int except;
  int can_write;
  int to_read;
  int r;

  enter_function();

  to_read = len - buffer_get_rest_len(s->in_buffer);

  if (to_read <= 0) {
    leave_function();
    return SSH_OK;
  }

  if (session->blocking) {
    buf = malloc(to_read);
    if (buf == NULL) {
      leave_function();
      return SSH_ERROR;
    }

    r = ssh_socket_completeread(session->socket,buf,to_read);
    if (r == SSH_ERROR || r == 0) {
      ssh_set_error(session, SSH_FATAL,
          (r == 0) ? "Connection closed by remote host" :
          "Error reading socket");
      ssh_socket_close(session->socket);
      session->alive = 0;
      SAFE_FREE(buf);

      leave_function();
      return SSH_ERROR;
    }

    if (buffer_add_data(s->in_buffer,buf,to_read) < 0) {
      SAFE_FREE(buf);
      leave_function();
      return SSH_ERROR;
    }

    SAFE_FREE(buf);

    leave_function();
    return SSH_OK;
  }

  /* nonblocking read */
  do {
    /* internally sets data_to_read */
    r = ssh_socket_poll(s, &can_write, &except);
    if (r < 0 || !s->data_to_read) {
      leave_function();
      return SSH_AGAIN;
    }

    /* read as much as we can */
    if (ssh_socket_is_open(session->socket)) {
      r = ssh_socket_unbuffered_read(session->socket, buffer, sizeof(buffer));
    } else {
      r =- 1;
    }

    if (r <= 0) {
      ssh_set_error(session, SSH_FATAL,
          (r == 0) ? "Connection closed by remote host" :
          "Error reading socket");
      ssh_socket_close(session->socket);
      session->alive = 0;

      leave_function();
      return SSH_ERROR;
    }

    if (buffer_add_data(s->in_buffer,buffer, (uint32_t) r) < 0) {
      leave_function();
      return SSH_ERROR;
    }
  } while(buffer_get_rest_len(s->in_buffer) < len);

  leave_function();
  return SSH_OK;
}

/* ssh_socket_poll */
int ssh_socket_poll(ssh_socket s, int *writeable, int *except) {
  ssh_session session = s->session;
  ssh_pollfd_t fd[1];
  int rc = -1;

  enter_function();

  if (!ssh_socket_is_open(s)) {
    *except = 1;
    *writeable = 0;
    return 0;
  }

  fd->fd = s->fd;
  fd->events = 0;

  if (!s->data_to_read) {
    fd->events |= POLLIN;
  }
  if (!s->data_to_write) {
    fd->events |= POLLOUT;
  }

  /* Make the call, and listen for errors */
  rc = ssh_poll(fd, 1, 0);
  if (rc < 0) {
    ssh_set_error(session, SSH_FATAL, "poll(): %s", strerror(errno));
    leave_function();
    return -1;
  }

  if (!s->data_to_read) {
    s->data_to_read = fd->revents & POLLIN;
  }
  if (!s->data_to_write) {
    s->data_to_write = fd->revents & POLLOUT;
  }
  if (!s->data_except) {
    s->data_except = fd->revents & POLLERR;
  }

  *except = s->data_except;
  *writeable = s->data_to_write;

  leave_function();
  return (s->data_to_read || (buffer_get_rest_len(s->in_buffer) > 0));
}

/** \internal
 * \brief starts a nonblocking flush of the output buffer
 *
 */
int ssh_socket_nonblocking_flush(ssh_socket s) {
  ssh_session session = s->session;
  int w;

  enter_function();

  if (!ssh_socket_is_open(s)) {
    session->alive = 0;
    /* FIXME use ssh_socket_get_errno */
    ssh_set_error(session, SSH_FATAL,
        "Writing packet: error on socket (or connection closed): %s",
        strerror(s->last_errno));

    leave_function();
    return SSH_ERROR;
  }

  if (s->data_to_write && buffer_get_rest_len(s->out_buffer) > 0) {
    w = ssh_socket_unbuffered_write(s, buffer_get_rest(s->out_buffer),
    		buffer_get_rest_len(s->out_buffer));
    if (w < 0) {
      session->alive = 0;
      ssh_socket_close(s);
      /* FIXME use ssh_socket_get_errno() */
      /* FIXME use callback for errors */
      ssh_set_error(session, SSH_FATAL,
          "Writing packet: error on socket (or connection closed): %s",
          strerror(s->last_errno));
      leave_function();
      return SSH_ERROR;
    }
    buffer_pass_bytes(s->out_buffer, w);
  }

  /* Is there some data pending? */
  if (buffer_get_rest_len(s->out_buffer) > 0 && s->poll) {
  	/* force the poll system to catch pollout events */
  	ssh_poll_set_events(s->poll, ssh_poll_get_events(s->poll) |POLLOUT);
    leave_function();
    return SSH_AGAIN;
  }

  /* all data written */
  leave_function();
  return SSH_OK;
}


/** \internal
 * \brief locking flush of the output packet buffer
 */
int ssh_socket_blocking_flush(ssh_socket s) {
  ssh_session session = s->session;

  enter_function();

  if (!ssh_socket_is_open(s)) {
    session->alive = 0;

    leave_function();
    return SSH_ERROR;
  }

  if (s->data_except) {
    leave_function();
    return SSH_ERROR;
  }

  if (buffer_get_rest_len(s->out_buffer) == 0) {
    leave_function();
    return SSH_OK;
  }

  if (ssh_socket_completewrite(s, buffer_get_rest(s->out_buffer),
        buffer_get_rest_len(s->out_buffer)) != SSH_OK) {
    session->alive = 0;
    ssh_socket_close(s);
    /* FIXME use the proper errno */
    ssh_set_error(session, SSH_FATAL,
        "Writing packet: error on socket (or connection closed): %s",
        strerror(errno));

    leave_function();
    return SSH_ERROR;
  }

  if (buffer_reinit(s->out_buffer) < 0) {
    leave_function();
    return SSH_ERROR;
  }

  leave_function();
  return SSH_OK; // no data pending
}

void ssh_socket_set_towrite(ssh_socket s) {
  s->data_to_write = 1;
}

void ssh_socket_set_toread(ssh_socket s) {
  s->data_to_read = 1;
}

void ssh_socket_set_except(ssh_socket s) {
  s->data_except = 1;
}

int ssh_socket_data_available(ssh_socket s) {
  return s->data_to_read;
}

int ssh_socket_data_writable(ssh_socket s) {
  return s->data_to_write;
}

int ssh_socket_get_status(ssh_socket s) {
  int r = 0;

  if (s->data_to_read) {
    r |= SSH_READ_PENDING;
  }

  if (s->data_except) {
    r |= SSH_CLOSED_ERROR;
  }

  return r;
}

/**
 * @internal
 * @brief Launches a socket connection
 * If a the socket connected callback has been defined and
 * a poll object exists, this call will be non blocking.
 * @param s    socket to connect.
 * @param host hostname or ip address to connect to.
 * @param port port number to connect to.
 * @param bind_addr address to bind to, or NULL for default.
 * @returns SSH_OK socket is being connected.
 * @returns SSH_ERROR error while connecting to remote host.
 * @bug It only tries connecting to one of the available AI's
 * which is problematic for hosts having DNS fail-over.
 */

int ssh_socket_connect(ssh_socket s, const char *host, int port, const char *bind_addr){
	socket_t fd;
	ssh_session session=s->session;
	enter_function();
	if(s->state != SSH_SOCKET_NONE)
		return SSH_ERROR;
	fd=ssh_connect_host_nonblocking(s->session,host,bind_addr,port);
	ssh_log(session,SSH_LOG_PROTOCOL,"Nonblocking connection socket: %d",fd);
	if(fd < 0)
		return SSH_ERROR;
	ssh_socket_set_fd(s,fd);
	s->state=SSH_SOCKET_CONNECTING;
	/* POLLOUT is the event to wait for in a nonblocking connect */
	ssh_poll_set_events(ssh_socket_get_poll_handle(s),POLLOUT);
#ifdef _WIN32
	ssh_poll_add_events(ssh_socket_get_poll_handle(s),POLLWRNORM);
#endif
	leave_function();
	return SSH_OK;
}

/* @} */

/* vim: set ts=4 sw=4 et cindent: */
