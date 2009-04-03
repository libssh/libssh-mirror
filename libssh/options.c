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
 *
 * vim: ts=2 sw=2 et cindent
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#endif
#include <sys/types.h>
#include "libssh/priv.h"

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

SSH_OPTIONS *ssh_options_new(void) {
    SSH_OPTIONS *option;

    option = malloc(sizeof(SSH_OPTIONS));
    if (option == NULL) {
      return NULL;
    }

    memset(option,0,sizeof(SSH_OPTIONS));
    option->port=22; /* set the default port */
    option->fd=-1;
    option->ssh2allowed=1;
#ifdef HAVE_SSH1
    option->ssh1allowed=1;
#else
    option->ssh1allowed=0;
#endif
    option->bindport=22;
    return option;
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
int ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port) {
  if (opt == NULL) {
    return -1;
  }

  opt->port = port & 0xffff;
  opt->bindport = port & 0xffff;

  return 0;
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
SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt) {
  SSH_OPTIONS *new = NULL;
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
    new->host = strdup(opt->bindaddr);
    if (new->host == NULL) {
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
  new->auth_function = opt->auth_function;
  new->auth_userdata = opt->auth_userdata;
  new->connect_status_function = opt->connect_status_function;
  new->connect_status_arg = opt->connect_status_arg;
  new->timeout = opt->timeout;
  new->timeout_usec = opt->timeout_usec;
  new->ssh2allowed = opt->ssh2allowed;
  new->ssh1allowed = opt->ssh1allowed;
  new->log_function = opt->log_function;
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
void ssh_options_free(SSH_OPTIONS *opt) {
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

/**
 * @brief Set destination hostname
 *
 * @param opt           The option structure to use.
 *
 * @param hostname      The host name to connect.
 *
 * @return 0 on succes, < 0 on error.
 */
int ssh_options_set_host(SSH_OPTIONS *opt, const char *hostname){
  char *h;
  char *p;

  if (opt == NULL || hostname == NULL) {
    return -1;
  }

  h = strdup(hostname);
  if (h == NULL) {
    return -1;
  }
  p = strchr(h, '@');

  SAFE_FREE(opt->host);

  if (p) {
    *p = '\0';
    opt->host = strdup(p + 1);
    if (opt->host == NULL) {
      SAFE_FREE(h);
      return -1;
    }

    SAFE_FREE(opt->username);
    opt->username = strdup(h);
    SAFE_FREE(h);
    if (opt->username == NULL) {
      return -1;
    }
  } else {
    opt->host = h;
  }

  return 0;
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
int ssh_options_set_username(SSH_OPTIONS *opt, const char *username) {
  if (opt == NULL || username == NULL) {
    return -1;
  }

  SAFE_FREE(opt->username);
  opt->username = strdup(username);
  if (opt->username == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_fd(SSH_OPTIONS *opt, socket_t fd) {
  if (opt == NULL) {
    return -1;
  }
  opt->fd = fd;

  return 0;
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
int ssh_options_set_bind(SSH_OPTIONS *opt, const char *bindaddr, int port) {
  if (opt == NULL || bindaddr == NULL) {
    return -1;
  }

  SAFE_FREE(opt->bindaddr);
  opt->bindaddr = strdup(bindaddr);
  if (opt->bindaddr == NULL) {
    return -1;
  }
  opt->bindport = port;

  return 0;
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
int ssh_options_set_ssh_dir(SSH_OPTIONS *opt, const char *dir) {
  char buffer[1024] = {0};

  if (opt == NULL || dir == NULL) {
    return -1;
  }

  snprintf(buffer, 1024, dir, ssh_get_user_home_dir());
  SAFE_FREE(opt->ssh_dir);
  opt->ssh_dir = strdup(buffer);
  if (opt->ssh_dir == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, const char *dir){
  char buffer[1024] = {0};

  if (opt == NULL || dir == NULL) {
    return -1;
  }

  snprintf(buffer, 1024, dir, ssh_get_user_home_dir());
  SAFE_FREE(opt->known_hosts_file);
  opt->known_hosts_file = strdup(buffer);
  if (opt->known_hosts_file == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_identity(SSH_OPTIONS *opt, const char *identity){
  char buffer[1024] = {0};

  if (opt == NULL || identity == NULL) {
    return -1;
  }

  snprintf(buffer, 1024, identity, ssh_get_user_home_dir());
  SAFE_FREE(opt->identity);
  opt->identity = strdup(buffer);
  if (opt->identity == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, const char *dsakey) {
  if (opt == NULL || dsakey == NULL) {
    return -1;
  }

  opt->dsakey = strdup(dsakey);
  if (opt->dsakey == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, const char *rsakey) {
  if (opt == NULL || rsakey == NULL) {
    return -1;
  }

  opt->rsakey = strdup(rsakey);
  if (opt->rsakey == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_banner(SSH_OPTIONS *opt, const char *banner) {
  if (opt == NULL || banner == NULL) {
    return -1;
  }

  SAFE_FREE(opt->banner);
  opt->banner = strdup(banner);
  if (opt->banner == NULL) {
    return -1;
  }

  return 0;
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
int ssh_options_set_wanted_algos(SSH_OPTIONS *opt, int algo, const char *list) {
  if (opt == NULL || list == NULL) {
    return -1;
  }

  if(algo > SSH_LANG_S_C || algo < 0) {
    ssh_set_error(opt, SSH_REQUEST_DENIED, "algo %d out of range", algo);
    return -1;
  }

  if ((!opt->use_nonexisting_algo) && !verify_existing_algo(algo, list)) {
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

#ifndef _WIN32
static char *get_username_from_uid(SSH_OPTIONS *opt, uid_t uid){
    struct passwd *pwd = NULL;

    pwd = getpwuid(uid);

    if (pwd == NULL) {
      ssh_set_error(opt,SSH_FATAL,"uid %d doesn't exist !",uid);
      return NULL;
    }

    return strdup(pwd->pw_name);
}
#endif

/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(SSH_OPTIONS *opt) {
  char *user = NULL;

  if (opt->username) {
    return 0;
  }

#ifndef _WIN32
  user = get_username_from_uid(opt,getuid());
  if (user) {
    opt->username = user;
    return 0;
  }
#else
  DWORD Size = 0;
  GetUserName(NULL, &Size); //Get Size
  user = malloc(Size);
  if (user == NULL) {
    return -1;
  }
  if (GetUserName(user, &Size)) {
    opt->username=user;
    return 0;
  } else {
    SAFE_FREE(user);
  }
#endif
  return -1;
}

int ssh_options_default_ssh_dir(SSH_OPTIONS *opt) {
  char buffer[256] = {0};

  if (opt->ssh_dir) {
    return 0;
  }

  snprintf(buffer, 256, "%s/.ssh/", ssh_get_user_home_dir());
  opt->ssh_dir = strdup(buffer);
  if (opt->ssh_dir == NULL) {
    return -1;
  }

  return 0;
}

int ssh_options_default_known_hosts_file(SSH_OPTIONS *opt) {
  char buffer[1024] = {0};

  if (opt->known_hosts_file) {
    return 0;
  }

  if (ssh_options_default_ssh_dir(opt) < 0) {
    return -1;
  }

  snprintf(buffer, 1024, "%s/known_hosts", opt->ssh_dir);
  opt->known_hosts_file = strdup(buffer);
  if (opt->known_hosts_file == NULL) {
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
int ssh_options_set_status_callback(SSH_OPTIONS *opt,
    void (*callback)(void *arg, float status), void *arg) {
  if (opt == NULL || callback == NULL) {
    return -1;
  }

  opt->connect_status_function = callback;
  opt->connect_status_arg = arg;

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
int ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds, long usec) {
  if (opt == NULL) {
    return -1;
  }

  opt->timeout=seconds;
  opt->timeout_usec=usec;

  return 0;
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
int ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow) {
  if (opt == NULL) {
    return -1;
  }

  if (allow) {
    opt->ssh1allowed = 1;
  } else {
    opt->ssh1allowed = 0;
  }

  return 0;
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
int ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow) {
  if (opt == NULL) {
    return -1;
  }

  if (allow) {
    opt->ssh2allowed = 1;
  } else {
    opt->ssh2allowed = 0;
  }

  return 0;
}

/**
 * @brief Change the writer callback for logging.
 *
 * Default is a write on stderr.
 *
 * @param opt           The options structure to use.
 *
 * @param callback      A callback function for the printing.
 *
 * @return 0 on success, < 0 on error.
 *
 * @warning The message string may contain format string characters.
 */
int ssh_options_set_log_function(SSH_OPTIONS *opt,
    void (*callback)(const char *message, SSH_SESSION *session, int priority)) {
  if (opt == NULL || callback == NULL) {
    return -1;
  }

  opt->log_function = callback;

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
int ssh_options_set_log_verbosity(SSH_OPTIONS *opt, int verbosity) {
  if (opt == NULL) {
    return -1;
  }

  opt->log_verbosity = verbosity;

  return 0;
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
int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv) {
  char *user = NULL;
  char *cipher = NULL;
  char *localaddr = NULL;
  char *identity = NULL;
  char **save = NULL;
  int i = 0;
  int argc = *argcptr;
  int port = 22;
  int debuglevel = 0;
  int usersa = 0;
  int usedss = 0;
  int compress = 0;
  int cont = 1;
  int current = 0;
#ifdef HAVE_SSH1
  int ssh1 = 1;
#else
  int ssh1 = 0;
#endif
  int ssh2 = 1;

  int saveoptind = optind; /* need to save 'em */
  int saveopterr = opterr;

  save = malloc(argc * sizeof(char *));
  if (save == NULL) {
    return -1;
  }

  opterr = 0; /* shut up getopt */
  while(cont && ((i = getopt(argc, argv, "c:i:Cl:p:vb:rd12")) != -1)) {
    switch(i) {
      case 'l':
        user = optarg;
        break;
      case 'p':
        port = atoi(optarg) & 0xffff;
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

  ssh_options_set_log_verbosity(options, debuglevel);

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
    if (ssh_options_set_wanted_algos(options, SSH_CRYPT_C_S, cipher) < 0) {
      cont = 0;
    }
    if (cont && ssh_options_set_wanted_algos(options, SSH_CRYPT_S_C, cipher) < 0) {
      cont = 0;
    }
  }

  if (cont && usersa) {
    if (ssh_options_set_wanted_algos(options, SSH_HOSTKEYS, "ssh-rsa") < 0) {
      cont = 0;
    }
  }

  if (cont && usedss) {
    if (ssh_options_set_wanted_algos(options, SSH_HOSTKEYS, "ssh-dss") < 0) {
      cont = 0;
    }
  }

  if (cont && user) {
    if (ssh_options_set_username(options, user) < 0) {
      cont = 0;
    }
  }

  if (cont && identity) {
    if (ssh_options_set_identity(options, identity) < 0) {
      cont = 0;
    }
  }

  if (cont && localaddr) {
    if (ssh_options_set_bind(options, localaddr, 0) < 0) {
      cont = 0;
    }
  }

  ssh_options_set_port(options, port);
  ssh_options_allow_ssh1(options, ssh1);
  ssh_options_allow_ssh2(options, ssh2);

  if (!cont) {
    return -1;
  }

  return 0;
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
int ssh_options_set_auth_callback(SSH_OPTIONS *opt, ssh_auth_callback cb,
    void *userdata) {
  if (opt == NULL || cb == NULL) {
    return -1;
  }

  opt->auth_function = cb;
  opt->auth_userdata = userdata;

  return 0;
}

/** @} */
