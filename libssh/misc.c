/*
 * misc.c - useful client functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003      by Aris Adamantiadis
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
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
 *
 * vim: ts=2 sw=2 et cindent
 */

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "config.h"

#ifdef _WIN32
#define _WIN32_IE 0x0400 //SHGetSpecialFolderPath
#include <shlobj.h>
#include <winsock2.h>
#else
#include <pwd.h>
#endif

#include "libssh/priv.h"

#ifdef HAVE_LIBGCRYPT
#define GCRYPT_STRING "/gnutls"
#else
#define GCRYPT_STRING ""
#endif

#ifdef HAVE_LIBCRYPTO
#define CRYPTO_STRING "/openssl"
#else
#define CRYPTO_STRING ""
#endif

#if defined(HAVE_LIBZ) && defined(WITH_LIBZ)
#define LIBZ_STRING "/zlib"
#else
#define LIBZ_STRING ""
#endif

/** \defgroup ssh_misc SSH Misc
 * \brief Misc functions
 */
/** \addtogroup ssh_misc
 * @{ */

#ifdef _WIN32

char *ssh_get_user_home_dir(void) {
  static char szPath[MAX_PATH] = {0};

  if (SHGetSpecialFolderPathA(NULL, szPath, CSIDL_PROFILE, TRUE)) {
    return szPath;
  }

  return NULL;
}
#else /* _WIN32 */

char *ssh_get_user_home_dir(void) {
  static char szPath[PATH_MAX] = {0};
  struct passwd *pwd = NULL;

  pwd = getpwuid(getuid());
  if (pwd == NULL) {
    return NULL;
  }

  snprintf(szPath, PATH_MAX - 1, "%s", pwd->pw_dir);

  return szPath;
}

#endif

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file) {
  if (access(file, R_OK) < 0) {
    return 0;
  }

  return 1;
}

u64 ntohll(u64 a) {
#ifdef WORDS_BIGENDIAN
  return a;
#else
  u32 low = a & 0xffffffff;
  u32 high = a >> 32 ;
  low = ntohl(low);
  high = ntohl(high);

  return ((((u64) low) << 32) | ( high));
#endif
}

/**
 * @brief Check if libssh is the required version or get the version
 * string.
 *
 * @param req_version   The version required.
 *
 * @return              If the version of libssh is newer than the version
 *                      required it will return a version string.
 *                      NULL if the version is older.
 *
 * Example:
 *
 * @code
 *  if (ssh_version(SSH_VERSION_INT(0,2,1)) == NULL) {
 *    fprintf(stderr, "libssh version is too old!\n");
 *    exit(1);
 *  }
 *
 *  if (debug) {
 *    printf("libssh %s\n", ssh_version(0));
 *  }
 * @endcode
 */
const char *ssh_version(int req_version) {
  if (req_version <= LIBSSH_VERSION_INT) {
    return SSH_STRINGIFY(LIBSSH_VERSION) GCRYPT_STRING CRYPTO_STRING
      LIBZ_STRING;
  }

  return NULL;
}

/** @} */

