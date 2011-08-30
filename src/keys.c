/*
 * keys.c - decoding a public key or signature and verifying them
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2005 by Aris Adamantiadis
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

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#endif
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/server.h"
#include "libssh/buffer.h"
#include "libssh/agent.h"
#include "libssh/session.h"
#include "libssh/keys.h"
#include "libssh/dh.h"
#include "libssh/messages.h"
#include "libssh/string.h"

/**
 * @addtogroup libssh_auth
 *
 * @{
 */

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
