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
#include <errno.h>
#include <pthread.h>

static int gcry_pthread_mutex_init (void **priv){
  int err = 0;
  pthread_mutex_t *lock = malloc (sizeof (pthread_mutex_t));

  if (!lock)
    err = ENOMEM;
  if (!err)
  {
    err = pthread_mutex_init (lock, NULL);
    if (err)
      free (lock);
    else
      *priv = lock;
  }
  return err;
}

static int gcry_pthread_mutex_destroy (void **lock) {
  int err = pthread_mutex_destroy ((pthread_mutex_t*)*lock);
  free (*lock);
  return err;
}
static int gcry_pthread_mutex_lock (void **lock) {
  return pthread_mutex_lock ((pthread_mutex_t*)*lock);
}
static int gcry_pthread_mutex_unlock (void **lock){
  return pthread_mutex_unlock ((pthread_mutex_t*)*lock);
}


static struct gcry_thread_cbs gcrypt_threads=
{
    .option=GCRY_THREAD_OPTION_VERSION << 8 || GCRY_THREAD_OPTION_PTHREAD,
    .mutex_init=gcry_pthread_mutex_init,
    .mutex_destroy=gcry_pthread_mutex_destroy,
    .mutex_lock=gcry_pthread_mutex_lock,
    .mutex_unlock=gcry_pthread_mutex_unlock
};

#endif

static struct ssh_threads_callbacks_struct *user_callbacks;
/** @internal
 * @brief inits the threading with the backend cryptographic libraries
 */

int ssh_threads_init(void){
#ifdef HAVE_LIBGCRYPT
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcrypt_threads);
#else


#endif
  return 0;
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
