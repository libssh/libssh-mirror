/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 Aris Adamantiadis <aris@0xbadc0de.be>
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

/* callback.h
 * This file includes the declarations for the libssh callback mechanism
 */

#include "libssh.h"

typedef int (*ssh_callback_int) (ssh_session session, void *user, int code);
typedef int (*ssh_message_callback) (ssh_session, void *user, ssh_message message);
typedef int (*ssh_channel_callback_int) (ssh_channel channel, void *user, int code);
typedef int (*ssh_channel_callback_data) (ssh_channel channel, void *user, int code, void *data, int len);

struct ssh_callbacks_struct {
  ssh_callback_int connection_progress;
  void *connection_progress_user;
  ssh_channel_callback_int channel_write_confirm;
  void *channel_write_confirm_user;
  ssh_channel_callback_data channel_read_available;
  void *channel_read_available_user;
};

typedef struct ssh_callbacks_struct * ssh_callbacks;

