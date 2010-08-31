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

/**
 * @defgroup libssh_threads Threading with libssh
 * @ingroup libssh
 *
 * Threading with libssh
 * @{
 */

#include "libssh/priv.h"
#include "libssh/threads.h"


#ifdef HAVE_LIBGCRYPT
#define HAVE_PTHREADS
#ifdef HAVE_PTHREADS
#include <errno.h>
#include <pthread.h>

static int ssh_pthread_mutex_init (void **priv){
  int err = 0;
  *priv = malloc (sizeof (pthread_mutex_t));

  if (*priv==NULL)
    return ENOMEM;
  err = pthread_mutex_init (*priv, NULL);
  if (err != 0){
    free (*priv);
    *priv=NULL;
  }
  return err;
}

static int ssh_pthread_mutex_destroy (void **lock) {
  int err = pthread_mutex_destroy (*lock);
  free (*lock);
  *lock=NULL;
  return err;
}

static int ssh_pthread_mutex_lock (void **lock) {
  return pthread_mutex_lock (*lock);
}

static int ssh_pthread_mutex_unlock (void **lock){
  return pthread_mutex_unlock (*lock);
}


static struct ssh_threads_callbacks_struct ssh_gcrypt_user_callbacks=
{
    .mutex_init=ssh_pthread_mutex_init,
    .mutex_destroy=ssh_pthread_mutex_destroy,
    .mutex_lock=ssh_pthread_mutex_lock,
    .mutex_unlock=ssh_pthread_mutex_unlock
};

#endif

static struct gcry_thread_cbs gcrypt_threads_callbacks;

#endif

static struct ssh_threads_callbacks_struct *user_callbacks;

#ifdef HAVE_LIBGCRYPT
static void copy_callback(struct ssh_threads_callbacks_struct *cb){
	gcrypt_threads_callbacks.option= GCRY_THREAD_OPTION_VERSION << 8 || GCRY_THREAD_OPTION_USER;
	gcrypt_threads_callbacks.mutex_init=cb->mutex_init;
	gcrypt_threads_callbacks.mutex_destroy=cb->mutex_destroy;
	gcrypt_threads_callbacks.mutex_lock=cb->mutex_lock;
	gcrypt_threads_callbacks.mutex_unlock=cb->mutex_unlock;
}
#endif

/** @internal
 * @brief inits the threading with the backend cryptographic libraries
 */

int ssh_threads_init(void){
#ifdef HAVE_LIBGCRYPT
	if(user_callbacks != NULL){
		copy_callback(user_callbacks);
		gcry_control(GCRYCTL_SET_THREAD_CBS, &gcrypt_threads_callbacks);
		return SSH_OK;
	}
#ifdef HAVE_PTHREADS
	else {
		copy_callback(&ssh_gcrypt_user_callbacks);
		gcry_control(GCRYCTL_SET_THREAD_CBS, &gcrypt_threads_callbacks);
		return SSH_OK;
	}
#endif
#else


#endif
  return SSH_ERROR;
}

int ssh_init_set_threads_callbacks(struct ssh_threads_callbacks_struct *cb){
  user_callbacks=cb;
  return SSH_OK;
}

int ssh_init_set_threads_pthreads(void){
  return SSH_OK;
}
/**
 * @}
 */
