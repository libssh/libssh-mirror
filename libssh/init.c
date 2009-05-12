/*
 * init.c - initialization and finalization of the library
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2006 by Aris Adamantiadis
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
#ifdef _WIN32
#include <winsock2.h>
#endif

/**
 * \addtogroup ssh_session
 * @{
 */

/**
 * @brief Finalize and cleanup all libssh and cryptographic data structures.
 *
 * This function should only be called once, at the end of the program!
 *
 * @returns 0
 */
int ssh_finalize(void) {
  ssh_crypto_finalize();
#ifdef HAVE_LIBGCRYPT
  gcry_control(GCRYCTL_TERM_SECMEM);
#elif defined HAVE_LIBCRYPTO
  EVP_cleanup();
#endif
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

/**
 * @}
 */
/* vim: set ts=2 sw=2 et cindent: */
