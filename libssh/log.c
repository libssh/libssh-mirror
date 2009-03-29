/*
 * log.c - logging and debugging functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008      by Aris Adamantiadis
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

#include "libssh/priv.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/** \defgroup ssh_log SSH Logging
 * \brief Logging functions for debugging and problem resolving
 */
/** \addtogroup ssh_log
 * @{ */

/** \brief logs an event
 * \param session the SSH session
 * \param verbosity verbosity of the event
 * \param format format string of the log entry
 */
void ssh_log(SSH_SESSION *session, int verbosity, const char *format, ...) {
	char buffer[1024];
	char buf2[256];
	int min;
	va_list va;
	if(verbosity <= session->log_verbosity){
		va_start(va,format);
		vsnprintf(buffer,sizeof(buffer),format,va);
		va_end(va);
		if(session->options->log_function)
			session->options->log_function(buffer,session,verbosity);
		else if(verbosity==SSH_LOG_FUNCTIONS){
			if(session->log_indent > 255)
				min=255;
			else
				min=session->log_indent;
			memset(buf2,' ',min);
			buf2[min]=0;
			fprintf(stderr,"[func] %s%s\n",buf2,buffer);
		} else {
			fprintf(stderr,"[%d] %s\n",verbosity,buffer);
		}
	}
}

/** @} */
