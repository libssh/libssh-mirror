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

#ifndef BENCHMARKS_H_
#define BENCHMARKS_H_

#include <libssh/libssh.h>

/* latency.c */

struct timestamp_struct {
  struct timeval timestamp;
};

int benchmarks_ping_latency (const char *host, float *average);
int benchmarks_ssh_latency (ssh_session session, float *average);

void timestamp_init(struct timestamp_struct *ts);
float elapsed_time(struct timestamp_struct *ts);

#endif /* BENCHMARKS_H_ */
