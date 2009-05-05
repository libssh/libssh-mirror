/*
 * error.c - functions for ssh error handling
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include <stdio.h>
#include <stdarg.h>
#include "libssh/priv.h"

/**
 * @defgroup ssh_error SSH Errors
 *
 * @brief Functions for error handling.
 */

/**
 * @addtogroup ssh_error
 * @{
 */

/**
 * @internal
 *
 * @brief Registers an error with a description.
 *
 * @param  error       The class of error.
 *
 * @param  code        The class of error.
 *
 * @param  descr       The description, which can be a format string.
 *
 * @param  ...         The arguments for the format string.
 */
void ssh_set_error(void *error, int code, const char *descr, ...) {
  struct error_struct *err = error;
  va_list va;
  va_start(va, descr);
  vsnprintf(err->error_buffer, ERROR_BUFFERLEN, descr, va);
  va_end(va);
  err->error_code = code;
}

/**
 * @brief Retrieve the error text message from the last error.
 *
 * @param  error        The SSH session pointer.
 *
 * @return A static string describing the error.
 */
const char *ssh_get_error(void *error) {
  struct error_struct *err = error;

  return err->error_buffer;
}

/**
 * @brief Retrieve the error code from the last error.
 *
 * @param  error        The SSH session pointer.
 *
 * \return SSH_NO_ERROR       No error occured\n
 *         SSH_REQUEST_DENIED The last request was denied but situation is
 *                            recoverable\n
 *         SSH_FATAL          A fatal error occured. This could be an unexpected
 *                            disconnection\n
 *
 *         \nOther error codes are internal but can be considered same than
 *         SSH_FATAL.
 */
int ssh_get_error_code(void *error) {
  struct error_struct *err = error;

  return err->error_code;
}

/** @} */

