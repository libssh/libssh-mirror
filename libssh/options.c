/*
 * options.c - handle pre-connection options
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <mail@cynapses.org>
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#else
#include <winsock2.h>
#endif
#include <sys/types.h>
#include "libssh/priv.h"
#include "libssh/options.h"
#include "libssh/misc.h"

/** \defgroup ssh_options SSH Options
 * \brief options settings for a new SSH session
 */
/** \addtogroup ssh_options
 * @{ */

/** This structure is freed automaticaly by ssh_disconnect()
 * when you use it. \n
 * It can be used by only one ssh_connect(), not more.\n
 * also by default, ssh1 support is not allowed
 *
 * \brief initializes a new option structure
 * \returns an empty intialized option structure.
 * \see ssh_options_getopt()
*/

ssh_options ssh_options_new(void) {
    ssh_options option;

    option = malloc(sizeof(struct ssh_options_struct));
    if (option == NULL) {
      return NULL;
    }
    ZERO_STRUCTP(option);
    option->port=22; /* set the default port */
    option->fd=-1;
    option->ssh2allowed=1;
#ifdef WITH_SSH1
    option->ssh1allowed=1;
#else
    option->ssh1allowed=0;
#endif
    option->bindport=22;
    return option;
}

/**
 * @brief Duplicate an option structure.
 *
 * If you make several sessions with the same options this is useful. You
 * cannot use twice the same option structure in ssh_session_connect.
 *
 * @param opt           Option structure to copy.
 *
 * @returns New copied option structure, NULL on error.
 *
 * @see ssh_session_connect()
 */
ssh_options ssh_options_copy(ssh_options opt) {
  ssh_options new = NULL;
  int i;

  if (opt == NULL) {
    return NULL;
  }

  new = ssh_options_new();
  if (new == NULL) {
    return NULL;
  }

  if (opt->username) {
    new->username = strdup(opt->username);
    if (new->username == NULL) {
      goto err;
    }
  }
  if (opt->host) {
    new->host = strdup(opt->host);
    if (new->host == NULL) {
      goto err;
    }
  }
  if (opt->bindaddr) {
    new->bindaddr = strdup(opt->bindaddr);
    if (new->bindaddr == NULL) {
      goto err;
    }
  }
  if (opt->identity) {
    new->identity=strdup(opt->identity);
    if (new->identity == NULL) {
      return NULL;
    }
  }
  if (opt->ssh_dir) {
    new->ssh_dir = strdup(opt->ssh_dir);
    if (new->ssh_dir == NULL) {
      goto err;
    }
  }
  if (opt->known_hosts_file) {
    new->known_hosts_file = strdup(opt->known_hosts_file);
    if (new->known_hosts_file == NULL) {
      goto err;
    }
  }
  if (opt->dsakey) {
    new->dsakey = strdup(opt->dsakey);
    if (new->dsakey == NULL) {
      goto err;
    }
  }
  if (opt->rsakey) {
    new->rsakey = strdup(opt->rsakey);
    if (new->rsakey == NULL) {
      goto err;
    }
  }
  for (i = 0; i < 10; ++i) {
    if (opt->wanted_methods[i]) {
      new->wanted_methods[i] = strdup(opt->wanted_methods[i]);
      if (new->wanted_methods[i] == NULL) {
        goto err;
      }
    }
  }

  new->fd = opt->fd;
  new->port = opt->port;
  new->callbacks = opt->callbacks;
  new->timeout = opt->timeout;
  new->timeout_usec = opt->timeout_usec;
  new->ssh2allowed = opt->ssh2allowed;
  new->ssh1allowed = opt->ssh1allowed;
  new->log_verbosity = opt->log_verbosity;

  return new;
err:
  ssh_options_free(new);
  return NULL;
}

/**
 * @brief Frees an option structure.
 *
 * @param opt           Option structure to free.
 */
void ssh_options_free(ssh_options opt) {
  int i;

  if (opt == NULL) {
    return;
  }

  /*
   * We don't touch the banner. If the implementation
   * did use it, they have to free it
   */

  SAFE_FREE(opt->username);
  SAFE_FREE(opt->host);
  SAFE_FREE(opt->identity);
  SAFE_FREE(opt->bindaddr);
  SAFE_FREE(opt->ssh_dir);
  SAFE_FREE(opt->known_hosts_file);
  SAFE_FREE(opt->dsakey);
  SAFE_FREE(opt->rsakey);

  for (i = 0; i < 10; i++) {
    if (opt->wanted_methods[i]) {
      free(opt->wanted_methods[i]);
    }
  }
  ZERO_STRUCTP(opt);
  SAFE_FREE(opt);
}

#ifndef _WIN32
static char *get_username_from_uid(ssh_options opt, uid_t uid){
    struct passwd *pwd = NULL;

    pwd = getpwuid(uid);

    if (pwd == NULL) {
      ssh_set_error(opt,SSH_FATAL,"uid %d doesn't exist !",uid);
      return NULL;
    }

    return strdup(pwd->pw_name);
}
#endif

static int ssh_options_set_algo(ssh_options opt, int algo, const char *list) {
  if (!verify_existing_algo(algo, list)) {
    ssh_set_error(opt, SSH_REQUEST_DENIED,
        "Setting method: no algorithm for method \"%s\" (%s)\n",
        ssh_kex_nums[algo], list);
    return -1;
  }

  SAFE_FREE(opt->wanted_methods[algo]);
  opt->wanted_methods[algo] = strdup(list);
  if (opt->wanted_methods[algo] == NULL) {
    return -1;
  }

  return 0;
}

static char *dir_expand_dup(ssh_options opt, const char *value, int allowsshdir) {
	char *new;

	if (value[0] == '~' && value[1] == '/') {
		const char *homedir = ssh_get_user_home_dir();
		size_t lv = strlen(value + 1), lh = strlen(homedir);

		new = malloc(lv + lh + 1);
		if (new == NULL)
			return NULL;
		memcpy(new, homedir, lh);
		memcpy(new + lh, value + 1, lv + 1);
		return new;
	}
	if (allowsshdir && strncmp(value, "SSH_DIR/", 8) == 0) {
		size_t lv, ls;
		if (opt->ssh_dir == NULL) {
			if (ssh_options_set(opt, SSH_OPTIONS_SSH_DIR, NULL) < 0)
				return NULL;
		}

		value += 7;
		lv = strlen(value);
		ls = strlen(opt->ssh_dir);

		new = malloc(lv + ls + 1);
		if (new == NULL)
			return NULL;
		memcpy(new, opt->ssh_dir, ls);
		memcpy(new + ls, value, lv + 1);
		return new;
	}
	return strdup(value);
}

/**
 * @brief This function can set all possible ssh options.
 *
 * @param  opt          An allocated ssh option structure.
 *
 * @param  type         The option type to set. This could be one of the
 *                      following:
 *
 *                      SSH_OPTIONS_HOST:
 *                        The hostname or ip address to connect to (string).
 *
 *                      SSH_OPTIONS_PORT:
 *                        The port to connect to (integer).
 *
 *                      SSH_OPTIONS_PORT_STR:
 *                        The port to connect to (string).
 *
 *                      SSH_OPTIONS_FD:
 *                        The file descriptor to use (socket_t).
 *
 *                        If you wish to open the socket yourself for a reason
 *                        or another, set the file descriptor. Don't forget to
 *                        set the hostname as the hostname is used as a key in
 *                        the known_host mechanism.
 *
 *                      SSH_OPTIONS_USER:
 *                        The username for authentication (string).
 *
 *                        If the value is NULL, the username is set to the
 *                        default username.
 *
 *                      SSH_OPTIONS_SSH_DIR:
 *                        Set the ssh directory (format string).
 *
 *                        If the value is NULL, the directory is set to the
 *                        default ssh directory.
 *
 *                        The ssh directory is used for files like known_hosts
 *                        and identity (private and public key). It may include
 *                        "%s" which will be replaced by the user home
 *                        directory.
 *
 *                      SSH_OPTIONS_KNOWNHOSTS:
 *                        Set the known hosts file name (format string).
 *
 *                        If the value is NULL, the directory is set to the
 *                        default known hosts file, normally ~/.ssh/known_hosts.
 *
 *                        The known hosts file is used to certify remote hosts
 *                        are genuine. It may include "%s" which will be
 *                        replaced by the user home directory.
 *
 *                      SSH_OPTIONS_IDENTITY:
 *                        Set the identity file name (format string).
 *
 *                        By default identity, id_dsa and id_rsa are checked.
 *
 *                        The identity file used authenticate with public key.
 *                        It may include "%s" which will be replaced by the
 *                        user home directory.
 *
 *                      SSH_OPTIONS_TIMEOUT:
 *                        Set a timeout for the connection in seconds (integer).
 *
 *                      SSH_OPTIONS_TIMEOUT_USEC:
 *                        Set a timeout for the connection in micro seconds
 *                        (integer).
 *
 *                      SSH_OPTIONS_SSH1:
 *                        Allow or deny the connection to SSH1 servers
 *                        (integer).
 *
 *                      SSH_OPTIONS_SSH2:
 *                        Allow or deny the connection to SSH2 servers
 *                        (integer).
 *
 *                      SSH_OPTIONS_LOG_VERBOSITY:
 *                        Set the session logging verbosity (integer).
 *
 *                        The verbosity of the messages. Every log smaller or
 *                        equal to verbosity will be shown.
 *                          SSH_LOG_NOLOG: No logging
 *                          SSH_LOG_RARE: Rare conditions or warnings
 *                          SSH_LOG_ENTRY: API-accessible entrypoints
 *                          SSH_LOG_PACKET: Packet id and size
 *                          SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *                      SSH_OPTTIONS_AUTH_CALLBACK:
 *                        Set a callback to use your own authentication function
 *                        (function pointer).
 *
 *                      SSH_OPTTIONS_AUTH_USERDATA:
 *                        Set the user data passed to the authentication function
 *                        (generic pointer).
 *
 *                      SSH_OPTTIONS_LOG_CALLBACK:
 *                        Set a callback to use your own logging function
 *                        (function pointer).
 *
 *                      SSH_OPTTIONS_LOG_USERDATA:
 *                        Set the user data passed to the logging function
 *                        (generic pointer).
 *
 *                      SSH_OPTTIONS_STATUS_CALLBACK:
 *                        Set a callback to show connection status in realtime
 *                        (function pointer).
 *
 *                        fn(void *arg, float status)
 *
 *                        During ssh_connect(), libssh will call the callback
 *                        with status from 0.0 to 1.0.
 *
 *                      SSH_OPTTIONS_STATUS_ARG:
 *                        Set the status argument which should be passed to the
 *                        status callback (generic pointer).
 *
 *                      SSH_OPTIONS_CIPHERS_C_S:
 *                        Set the symmetric cipher client to server (string,
 *                        comma-separated list).
 *
 *                      SSH_OPTIONS_CIPHERS_S_C:
 *                        Set the symmetric cipher server to client (string,
 *                        comma-separated list).
 *
 *                      SSH_OPTIONS_COMPRESSION_C_S:
 *                        Set the compression to use for client to server
 *                        communication (string, "none" or "zlib").
 *
 *                      SSH_OPTIONS_COMPRESSION_S_C:
 *                        Set the compression to use for server to client
 *                        communication (string, "none" or "zlib").
 *
 *                      SSH_OPTIONS_SERVER_BINDADDR:
 *                      SSH_OPTIONS_SERVER_HOSTKEY:
 *                        Set the server public key type: ssh-rsa or ssh-dss
 *                        (string).
 *
 *                      SSH_OPTIONS_SERVER_DSAKEY:
 *                        Set the path to the dsa ssh host key (string).
 *
 *                      SSH_OPTIONS_SERVER_RSAKEY:
 *                        Set the path to the ssh host rsa key (string).
 *
 *                      SSH_OPTIONS_SERVER_BANNER:
 *                        Set the server banner sent to clients (string).
 *
 * @param  value        The value to set. This is a generic pointer and the
 *                      datatype which is used should be set according to the
 *                      type set.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_options_set(ssh_options opt, enum ssh_options_e type,
    const void *value) {
  char *p, *q;
  int i;

  if (opt == NULL) {
    return -1;
  }

  switch (type) {
    case SSH_OPTIONS_HOST:
      q = strdup(value);
      if (q == NULL) {
        return -1;
      }
      p = strchr(q, '@');

      SAFE_FREE(opt->host);

      if (p) {
        *p = '\0';
        opt->host = strdup(p + 1);
        if (opt->host == NULL) {
          SAFE_FREE(q);
          return -1;
        }

        SAFE_FREE(opt->username);
        opt->username = strdup(q);
        SAFE_FREE(q);
        if (opt->username == NULL) {
          return -1;
        }
      } else {
        opt->host = q;
      }
      break;
    case SSH_OPTIONS_PORT:
      if (value == NULL) {
        opt->port = 22 & 0xffff;
      } else {
        int *x = (int *) value;

        opt->port = *x & 0xffff;
      }
      break;
    case SSH_OPTIONS_PORT_STR:
      if (value == NULL) {
        opt->port = 22 & 0xffff;
      } else {
        q = strdup(value);
        if (q == NULL) {
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        opt->port = i & 0xffff;
      }
      break;
    case SSH_OPTIONS_USER:
      SAFE_FREE(opt->username);
      if (value == NULL) { /* set default username */
#ifdef _WIN32
        DWORD size = 0;
        GetUserName(NULL, &size); //Get Size
        q = malloc(size);
        if (q == NULL) {
          return -1;
        }
        if (GetUserName(q, &size)) {
          opt->username = q;
        } else {
          SAFE_FREE(q);
          return -1;
        }
#else /* _WIN32 */
        q = get_username_from_uid(opt, getuid());
        if (q == NULL) {
          return -1;
        }
        opt->username = q;
#endif /* _WIN32 */
      } else { /* username provided */
        opt->username = strdup(value);
        if (opt->username == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_SSH_DIR:
      if (value == NULL) {
        SAFE_FREE(opt->ssh_dir);
	/* TODO: why ~/.ssh/ instead of ~/.ssh ? */

        opt->ssh_dir = dir_expand_dup(opt, "~/.ssh/", 0);
        if (opt->ssh_dir == NULL) {
          return -1;
        }
      } else {
        SAFE_FREE(opt->ssh_dir);
        opt->ssh_dir = dir_expand_dup(opt, value, 0);
        if (opt->ssh_dir == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_IDENTITY:

      if (value == NULL) {
        return -1;
      }
      SAFE_FREE(opt->identity);
      opt->identity = dir_expand_dup(opt, value, 1);
      if (opt->identity == NULL) {
        return -1;
      }
      break;
    case SSH_OPTIONS_KNOWNHOSTS:
      if (value == NULL) {
        SAFE_FREE(opt->known_hosts_file);
        opt->known_hosts_file = dir_expand_dup(opt,
			"SSH_DIR/known_hosts", 1);
        if (opt->known_hosts_file == NULL) {
          return -1;
        }
      } else {
        SAFE_FREE(opt->known_hosts_file);
        opt->known_hosts_file = dir_expand_dup(opt, value, 1);
        if (opt->known_hosts_file == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_TIMEOUT:
      if (value == NULL) {
        return -1;
      } else {
        long *x = (long *) value;

        opt->timeout = *x;
      }
      break;
    case SSH_OPTIONS_TIMEOUT_USEC:
      if (value == NULL) {
        return -1;
      } else {
        long *x = (long *) value;

        opt->timeout_usec = *x;
      }
      break;
    case SSH_OPTIONS_SSH1:
      if (value == NULL) {
        return -1;
      } else {
        int *x = (int *) value;
        opt->ssh1allowed = *x;
      }
      break;
    case SSH_OPTIONS_SSH2:
      if (value == NULL) {
        return -1;
      } else {
        int *x = (int *) value;
        opt->ssh2allowed = *x;
      }
      break;
    case SSH_OPTIONS_LOG_VERBOSITY:
      if (value == NULL) {
        return -1;
      } else {
        int *x = (int *) value;

        opt->log_verbosity = *x;
      }
    case SSH_OPTIONS_CIPHERS_C_S:
      if (value == NULL) {
        return -1;
      } else {
        ssh_options_set_algo(opt, SSH_CRYPT_C_S, value);
      }
      break;
    case SSH_OPTIONS_CIPHERS_S_C:
      if (value == NULL) {
        return -1;
      } else {
        ssh_options_set_algo(opt, SSH_CRYPT_S_C, value);
      }
      break;
    case SSH_OPTIONS_COMPRESSION_C_S:
      if (value == NULL) {
        return -1;
      } else {
        ssh_options_set_algo(opt, SSH_COMP_C_S, value);
      }
      break;
    case SSH_OPTIONS_COMPRESSION_S_C:
      if (value == NULL) {
        return -1;
      } else {
        ssh_options_set_algo(opt, SSH_COMP_S_C, value);
      }
      break;
    case SSH_OPTIONS_SERVER_HOSTKEY:
      if (value == NULL) {
        return -1;
      } else {
        ssh_options_set_algo(opt, SSH_HOSTKEYS, value);
      }
      break;
    case SSH_OPTIONS_SERVER_BINDADDR:
      if (value == NULL) {
        return -1;
      } else {
        opt->bindaddr = strdup(value);
        if (opt->bindaddr == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_SERVER_BINDPORT:
      if (value == NULL) {
        return -1;
      } else {
        int *x = (int *) value;
        opt->bindport = *x & 0xffff;
      }
      break;
    case SSH_OPTIONS_SERVER_DSAKEY:
      if (value == NULL) {
        return -1;
      } else {
        opt->dsakey = strdup(value);
        if (opt->dsakey == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_SERVER_RSAKEY:
      if (value == NULL) {
        return -1;
      } else {
        opt->rsakey = strdup(value);
        if (opt->rsakey == NULL) {
          return -1;
        }
      }
      break;
    case SSH_OPTIONS_SERVER_BANNER:
      if (value == NULL) {
        return -1;
      } else {
        opt->banner = strdup(value);
        if (opt->banner == NULL) {
          return -1;
        }
      }
      break;
    default:
      ssh_set_error(opt, SSH_REQUEST_DENIED, "Unkown ssh option %d", type);
      return -1;
    break;
  }

  return 0;
}

/**
 * @brief Set destination hostname
 *
 * @param opt           The option structure to use.
 *
 * @param hostname      The host name to connect.
 *
 * @return 0 on succes, < 0 on error.
 */
int ssh_options_set_host(ssh_options opt, const char *hostname){
  return ssh_options_set(opt, SSH_OPTIONS_HOST, hostname);
}

/**
 * @brief Set port to connect or to bind for a connection.
 *
 * @param opt           The options structure to use.
 *
 * @param port          The port to connect or to bind.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_port(ssh_options opt, unsigned int port) {
  return ssh_options_set(opt, SSH_OPTIONS_PORT, &port);
}

/**
 * @brief Set the username for authentication
 *
 * @param opt           The options structure to use.
 *
 * @param username      The username to authenticate.
 *
 * @return 0 on success, -1 on error.
 *
 * @bug this should not be set at options time
 */
int ssh_options_set_username(ssh_options opt, const char *username) {
  return ssh_options_set(opt, SSH_OPTIONS_USER, username);
}

/**
 * @brief Set a file descriptor for connection.
 *
 * If you wish to open the socket yourself for a reason or another, set the
 * file descriptor. Don't forget to use ssh_option_set_hostname() as the
 * hostname is used as a key in the known_host mechanism.
 *
 * @param opt           The options structure to use.
 *
 * @param fd            An opened file descriptor to use.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_fd(ssh_options opt, socket_t fd) {
  return ssh_options_set(opt, SSH_OPTIONS_FD, &fd);
}

/**
 * @brief Set the local address and port binding.
 *
 * In case your client has multiple IP adresses, select the local address and
 * port to use for the socket.\n
 * If the address or port is not bindable, it may be impossible to connect.
 *
 * @param opt           The options structure to use.
 *
 * @param bindaddr      The bind address in form of hostname or ip address.
 *
 * @param port          The port number to bind.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_bind(ssh_options opt, const char *bindaddr, int port) {
  int rc;

  rc = ssh_options_set(opt, SSH_OPTIONS_SERVER_BINDADDR, bindaddr);
  if (rc < 0) {
    return -1;
  }
  rc = ssh_options_set(opt, SSH_OPTIONS_SERVER_BINDPORT, &port);

  return rc;
}

/**
 * @brief Set the ssh directory.
 *
 * The ssh directory is used for files like known_hosts and identity (public
 * and private keys)
 *
 * @param opt           The options structure to use.
 *
 * @param dir           The directory to set. It may include "%s" which will be
 *                      replaced by the user home directory.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_user_home_dir()
 */
int ssh_options_set_ssh_dir(ssh_options opt, const char *dir) {
  return ssh_options_set(opt, SSH_OPTIONS_SSH_DIR, dir);
}

/**
 * @brief Set the known hosts file name.
 *
 * The known hosts file is used to certify remote hosts are genuine.
 *
 * @param opt           The options structure to use.
 *
 * @param dir           The path to the file including its name. "%s" will be
 *                      substitued with the user home directory.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_user_home_dir()
 */
int ssh_options_set_known_hosts_file(ssh_options opt, const char *dir){
  return ssh_options_set(opt, SSH_OPTIONS_KNOWNHOSTS, dir);
}

/**
 * @brief Set the identity file name.
 *
 * The identity file is used authenticate with public key.
 *
 * @param opt           The options structure to use.
 *
 * @param identity      The path to the file including its name. "%s" will be
 *                      substitued with the user home directory.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_user_home_dir()
 */
int ssh_options_set_identity(ssh_options opt, const char *identity){
  return ssh_options_set(opt, SSH_OPTIONS_IDENTITY, identity);
}

/**
 * @brief Set the path to the dsa ssh host key.
 *
 * @param  opt          The options structure to use.
 *
 * @param  dsakey       The path to the dsa key to set.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_dsa_server_key(ssh_options opt, const char *dsakey) {
  return ssh_options_set(opt, SSH_OPTIONS_SERVER_DSAKEY, dsakey);
}

/**
 * @brief Set the path to the ssh host rsa key.
 *
 * @param  opt          The options structure to use.
 *
 * @param  rsakey       The path to the rsa key to set.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_rsa_server_key(ssh_options opt, const char *rsakey) {
  return ssh_options_set(opt, SSH_OPTIONS_SERVER_RSAKEY, rsakey);
}

/**
 * @brief Set the server banner sent to clients.
 *
 * @param opt           The options structure to use.
 *
 * @param banner        A text banner to be shown.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_banner(ssh_options opt, const char *banner) {
  return ssh_options_set(opt, SSH_OPTIONS_SERVER_BANNER, banner);
}

/**
 * @brief Set the algorithms to be used for cryptography and compression.
 *
 * The methods are:\n
 * KEX_HOSTKEY (server public key type) : ssh-rsa or ssh-dss\n
 * KEX_CRYPT_C_S (symmetric cipher client to server)\n
 * KEX_CRYPT_S_C (symmetric cipher server to client)\n
 * KEX_COMP_C_S (Compression client to server): zlib or none\n
 * KEX_COMP_S_C (Compression server to client): zlib or none\n
 * You don't have to use this function if using the default ciphers
 * is okay for you\n
 * in order to enable compression client to server, do\n
 * @code
 * ret = ssh_options_set_wanted_algos(opt,KEX_COMP_C_S,"zlib");
 * @endcode
 *
 * @param opt           The options structure to use.
 *
 * @param algo          The method which needs to be changed.
 *
 * @param list          A list of algorithms to be used, in order of preference
 *                      and separated by commas.
 *
 * @return 0 on success, < 0 on error
 */
int ssh_options_set_wanted_algos(ssh_options opt, int algo, const char *list) {
  if (opt == NULL || list == NULL) {
    return -1;
  }

  if(algo > SSH_LANG_S_C || algo < 0) {
    ssh_set_error(opt, SSH_REQUEST_DENIED, "algo %d out of range", algo);
    return -1;
  }

  if (!verify_existing_algo(algo, list)) {
    ssh_set_error(opt, SSH_REQUEST_DENIED, "Setting method: no algorithm "
        "for method \"%s\" (%s)\n", ssh_kex_nums[algo], list);
    return -1;
  }

  SAFE_FREE(opt->wanted_methods[algo]);
  opt->wanted_methods[algo] = strdup(list);
  if (opt->wanted_methods[algo] == NULL) {
    return -1;
  }

  return 0;
}

/**
 * @brief Set a callback to show connection status in realtime.
 *
 * During ssh_connect(), libssh will call the callback with status from
 * 0.0 to 1.0
 *
 * @param opt           The options structure to use.
 *
 * @param callback      A function pointer to a callback in form
 *                      f(void *userarg, float status).
 *
 * @param arg           The value to be given as argument to the callback
 *                      function when it is called.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_connect()
 */
int ssh_options_set_status_callback(ssh_options opt,
    void (*callback)(void *arg, float status), void *arg) {
  if (opt == NULL || callback == NULL || opt->callbacks==NULL) {
    return -1;
  }

  opt->callbacks->connect_status_function = callback;
  if(arg)
  	opt->callbacks->userdata=arg;

  return 0;
}

/**
 * @brief Set a timeout for the connection.
 *
 * @param opt           The options structure to use.
 *
 * @param seconds       Number of seconds.
 *
 * @param usec          Number of micro seconds.
 *
 * @return 0 on success, < 0 on error.
 *
 * @bug Currently it only timeouts the socket connection, not the
 *      complete exchange.
 */
int ssh_options_set_timeout(ssh_options opt, long seconds, long usec) {
  if (ssh_options_set(opt, SSH_OPTIONS_TIMEOUT, &seconds) < 0) {
    return -1;
  }

  return ssh_options_set(opt, SSH_OPTIONS_TIMEOUT_USEC, &usec);
}

/**
 * @brief Allow or deny the connection to SSH1 servers.
 *
 * Default value is 0 (no connection to SSH1 servers).
 *
 * @param opt           The options structure to use.
 *
 * @param allow         Non zero value allow ssh1.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_allow_ssh1(ssh_options opt, int allow) {
  return ssh_options_set(opt, SSH_OPTIONS_SSH1, &allow);
}

/**
 * @brief Allow or deny the connection to SSH2 servers.
 *
 * Default value is 1 (allow connection to SSH2 servers).
 *
 * @param opt           The options structure to use.
 *
 * @param allow         Non zero values allow ssh2.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_allow_ssh2(ssh_options opt, int allow) {
  return ssh_options_set(opt, SSH_OPTIONS_SSH2, &allow);
}

/**
 * @brief Change the writer callback for logging.
 *
 * Default is a write on stderr.
 *
 * @param opt           The options structure to use.
 *
 * @param cb      			A callback function for the printing.
 *
 * @param userdata			Pointer to user-provided data
 *
 * @return 0 on success, < 0 on error.
 *
 * @warning The message string may contain format string characters.
 */
int ssh_options_set_log_function(ssh_options opt, ssh_log_callback cb,
      void *userdata) {
  if (opt == NULL || cb == NULL || opt->callbacks==NULL) {
    return -1;
  }

  opt->callbacks->log_function = cb;
  if(userdata)
  	opt->callbacks->userdata = userdata;

  return 0;
}

/**
 * @brief Set the session logging priority.
 *
 * @param opt           The options structure to use.
 *
 * @param verbosity     The verbosity of the messages. Every log smaller or
 *                      equal to verbosity will be shown\n
 *                      SSH_LOG_NOLOG No logging \n
 *                      SSH_LOG_RARE Rare conditions or warnings\n
 *                      SSH_LOG_ENTRY Api-accessible entrypoints\n
 *                      SSH_LOG_PACKET Packet id and size\n
 *                      SSH_LOG_FUNCTIONS function entering and leaving\n
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_log_verbosity(ssh_options opt, int verbosity) {
  return ssh_options_set(opt, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
}
/**
 * @brief Parse command line arguments.
 *
 * This is a helper for your application to generate the appropriate
 * options from the command line arguments.\n
 * The argv array and argc value are changed so that the parsed
 * arguments wont appear anymore in them.\n
 * The single arguments (without switches) are not parsed. thus,
 * myssh -l user localhost\n
 * The command wont set the hostname value of options to localhost.
 *
 * @param options       An empty option structure pointer.
 *
 * @param argcptr       The pointer to the argument count.
 *
 * @param argv          The arguments list pointer.
 *
 * @returns 0 on success, < 0 on error.
 *
 * @see ssh_options_new()
 */
int ssh_options_getopt(ssh_options options, int *argcptr, char **argv) {
  char *user = NULL;
  char *cipher = NULL;
  char *localaddr = NULL;
  char *identity = NULL;
  char *port = NULL;
  char *bindport = NULL;
  char **save = NULL;
  int i = 0;
  int argc = *argcptr;
  int debuglevel = 0;
  int usersa = 0;
  int usedss = 0;
  int compress = 0;
  int cont = 1;
  int current = 0;
#ifdef WITH_SSH1
  int ssh1 = 1;
#else
  int ssh1 = 0;
#endif
  int ssh2 = 1;
#ifdef _MSC_VER
    /* Not supported with a Microsoft compiler */
    return -1;
#else
  int saveoptind = optind; /* need to save 'em */
  int saveopterr = opterr;

  save = malloc(argc * sizeof(char *));
  if (save == NULL) {
    return -1;
  }

  opterr = 0; /* shut up getopt */
  while(cont && ((i = getopt(argc, argv, "c:i:Cl:p:vb:t:rd12")) != -1)) {
    switch(i) {
      case 'l':
        user = optarg;
        break;
      case 'p':
        port = optarg;
        break;
      case 't':
        bindport = optarg;
        break;
      case 'v':
        debuglevel++;
        break;
      case 'r':
        usersa++;
        break;
      case 'd':
        usedss++;
        break;
      case 'c':
        cipher = optarg;
        break;
      case 'i':
        identity = optarg;
        break;
      case 'b':
        localaddr = optarg;
        break;
      case 'C':
        compress++;
        break;
      case '2':
        ssh2 = 1;
        ssh1 = 0;
        break;
      case '1':
        ssh2 = 0;
        ssh1 = 1;
        break;
      default:
        {
          char opt[3]="- ";
          opt[1] = optopt;
          save[current] = strdup(opt);
          if (save[current] == NULL) {
            SAFE_FREE(save);
            return -1;
          }
          current++;
          if (optarg) {
            save[current++] = argv[optind + 1];
          }
        }
    } /* switch */
  } /* while */
  opterr = saveopterr;
  while (optind < argc) {
    save[current++] = argv[optind++];
  }

  if (usersa && usedss) {
    ssh_set_error(options, SSH_FATAL, "Either RSA or DSS must be chosen");
    cont = 0;
  }

  ssh_options_set(options, SSH_OPTIONS_LOG_VERBOSITY, &debuglevel);

  optind = saveoptind;

  if(!cont) {
    SAFE_FREE(save);
    return -1;
  }

  /* first recopy the save vector into the original's */
  for (i = 0; i < current; i++) {
    /* don't erase argv[0] */
    argv[ i + 1] = save[i];
  }
  argv[current + 1] = NULL;
  *argcptr = current + 1;
  SAFE_FREE(save);

  /* set a new option struct */
  if (compress) {
    if (ssh_options_set_wanted_algos(options, SSH_COMP_C_S, "zlib") < 0) {
      cont = 0;
    }
    if (ssh_options_set_wanted_algos(options, SSH_COMP_S_C, "zlib") < 0) {
      cont = 0;
    }
  }

  if (cont && cipher) {
    if (ssh_options_set(options, SSH_OPTIONS_CIPHERS_C_S, cipher) < 0) {
      cont = 0;
    }
    if (cont && ssh_options_set(options, SSH_OPTIONS_CIPHERS_S_C, cipher) < 0) {
      cont = 0;
    }
  }

  if (cont && usersa) {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_HOSTKEY, "ssh-rsa") < 0) {
      cont = 0;
    }
  }

  if (cont && usedss) {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_HOSTKEY, "ssh-dss") < 0) {
      cont = 0;
    }
  }

  if (cont && user) {
    if (ssh_options_set(options, SSH_OPTIONS_USER, user) < 0) {
      cont = 0;
    }
  }

  if (cont && identity) {
    if (ssh_options_set(options, SSH_OPTIONS_IDENTITY, identity) < 0) {
      cont = 0;
    }
  }

  if (cont && localaddr) {
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_BINDADDR, localaddr) < 0) {
      cont = 0;
    }
  }

  if (cont && bindport) {
    i = atoi(bindport);
    if (ssh_options_set(options, SSH_OPTIONS_SERVER_BINDPORT, &i) < 0) {
      cont = 0;
    }
  }

  ssh_options_set(options, SSH_OPTIONS_PORT_STR, port);

  ssh_options_set(options, SSH_OPTIONS_SSH1, &ssh1);
  ssh_options_set(options, SSH_OPTIONS_SSH2, &ssh2);

  if (!cont) {
    return -1;
  }

  return 0;
#endif
}

/**
 * @brief Set the authentication callback.
 *
 * @param opt           The options structure to use.
 *
 * @param cb            The callback function to use.
 *
 * @param userdata      A pointer to some user data you can pass to the
 *                      callback.
 *
 * @return 0 on success, < 0 on error.
 */
int ssh_options_set_auth_callback(ssh_options opt, ssh_auth_callback cb,
    void *userdata) {
  if (opt == NULL || cb == NULL || opt->callbacks==NULL) {
    return -1;
  }

  opt->callbacks->auth_function = cb;
  if(userdata != NULL)
  	opt->callbacks->userdata = userdata;

  return 0;
}

/**
 * @brief Parse the ssh config file.
 *
 * This should be the last call of all options, it may overwrite options which
 * are already set. It requires that the host name is already set with
 * ssh_options_set_host().
 *
 * @param  opt          The options structure to use.
 *
 * @param  filename     The options file to use, if NULL the default
 *                      ~/.ssh/config will be used.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_host()
 */
int ssh_options_parse_config(ssh_options opt, const char *filename) {
  char *expanded_filename;
  int r;

  if (opt == NULL || opt->host == NULL) {
    return -1;
  }

  /* set default filename */
  if (filename == NULL) {
    expanded_filename = dir_expand_dup(opt, "SSH_DIR/config", 1);
  } else {
    expanded_filename = dir_expand_dup(opt, filename, 1);
  }
  if (expanded_filename == NULL)
    return -1;

  r = ssh_config_parse_file(opt, expanded_filename);
  free(expanded_filename);
  return r;
}

/** @} */
/* vim: set ts=2 sw=2 et cindent: */
