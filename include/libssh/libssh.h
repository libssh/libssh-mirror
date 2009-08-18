/*
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
 */

#ifndef _LIBSSH_H
#define _LIBSSH_H

#ifndef _MSC_VER
#include <unistd.h>
#include <inttypes.h>
#else /* _MSC_VER */
//visual studio hasn't inttypes.h so it doesn't know uint32_t
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;
#endif /* _MSC_VER */

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h> /* for fd_set * */
#include <netdb.h>
#endif /* _WIN32 */

#define SSH_STRINGIFY(s) SSH_TOSTRING(s)
#define SSH_TOSTRING(s) #s

/* libssh version macros */
#define SSH_VERSION_INT(a, b, c) ((a) << 16 | (b) << 8 | (c))
#define SSH_VERSION_DOT(a, b, c) a ##.## b ##.## c
#define SSH_VERSION(a, b, c) SSH_VERSION_DOT(a, b, c)

/* libssh version */
#define LIBSSH_VERSION_MAJOR  0
#define LIBSSH_VERSION_MINOR  3
#define LIBSSH_VERSION_MICRO  3

#define LIBSSH_VERSION_INT SSH_VERSION_INT(LIBSSH_VERSION_MAJOR, \
                                           LIBSSH_VERSION_MINOR, \
                                           LIBSSH_VERSION_MICRO)
#define LIBSSH_VERSION     SSH_VERSION(LIBSSH_VERSION_MAJOR, \
                                       LIBSSH_VERSION_MINOR, \
                                       LIBSSH_VERSION_MICRO)

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct string_struct STRING;
typedef struct buffer_struct BUFFER;
typedef struct public_key_struct PUBLIC_KEY;
typedef struct private_key_struct PRIVATE_KEY;
typedef struct ssh_options_struct SSH_OPTIONS;
typedef struct channel_struct CHANNEL;
typedef struct agent_struct AGENT;
typedef struct ssh_session SSH_SESSION;
typedef struct ssh_kbdint SSH_KBDINT;

/* integer values */
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
typedef uint8_t u8;

/* Socket type */
#ifdef _WIN32
#define socket_t SOCKET
#else
typedef int socket_t;
#endif

/* the offsets of methods */
#define SSH_KEX 0
#define SSH_HOSTKEYS 1
#define SSH_CRYPT_C_S 2
#define SSH_CRYPT_S_C 3
#define SSH_MAC_C_S 4
#define SSH_MAC_S_C 5
#define SSH_COMP_C_S 6
#define SSH_COMP_S_C 7
#define SSH_LANG_C_S 8
#define SSH_LANG_S_C 9

#define SSH_CRYPT 2
#define SSH_MAC 3
#define SSH_COMP 4
#define SSH_LANG 5

#define SSH_AUTH_SUCCESS 0
#define SSH_AUTH_DENIED 1
#define SSH_AUTH_PARTIAL 2
#define SSH_AUTH_INFO 3
#define SSH_AUTH_ERROR -1

#define SSH_AUTH_METHOD_PASSWORD 0x0001
#define SSH_AUTH_METHOD_PUBLICKEY 0x0002
#define SSH_AUTH_METHOD_HOSTBASED 0x0004
#define SSH_AUTH_METHOD_INTERACTIVE 0x0008

/* status flags */

#define SSH_CLOSED (1<<0)
#define SSH_READ_PENDING (1<<1)
#define SSH_CLOSED_ERROR (1<<2)

#define SSH_SERVER_ERROR -1
#define SSH_SERVER_NOT_KNOWN 0
#define SSH_SERVER_KNOWN_OK 1
#define SSH_SERVER_KNOWN_CHANGED 2
#define SSH_SERVER_FOUND_OTHER 3
#define SSH_SERVER_FILE_NOT_FOUND 4

#ifndef MD5_DIGEST_LEN
    #define MD5_DIGEST_LEN 16
#endif
/* errors */

#define SSH_NO_ERROR 0
#define SSH_REQUEST_DENIED 1
#define SSH_FATAL 2
#define SSH_EINTR 3

/* Error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* Error of some kind */
#define SSH_AGAIN -2 /* The nonblocking call must be repeated */
#define SSH_EOF -127 /* We have already a eof */

const char *ssh_get_error(void *error); 
int ssh_get_error_code(void *error);

/* version checks */
const char *ssh_version(int req_version);

/** \addtogroup ssh_log
 * @{
 */
 /** \brief Verbosity level for logging and help to debugging 
  */

enum {
	/** No logging at all
	 */
	SSH_LOG_NOLOG=0,
	/** Only rare and noteworthy events
	 */
	SSH_LOG_RARE,
	/** High level protocol informations 
	 */
	SSH_LOG_PROTOCOL,
	/** Lower level protocol infomations, packet level
	 */
	SSH_LOG_PACKET, 
	/** Every function path
	 */
	SSH_LOG_FUNCTIONS 
};
/** @}
 */
/*#define SSH_LOG_NOLOG 0 // no log
#define SSH_LOG_RARE 1 // rare conditions
#define SSH_LOG_ENTRY 2 // user-accessible entrypoints
#define SSH_LOG_PACKET 3 // packet id and size
#define SSH_LOG_FUNCTIONS 4 // every function in and return
*/
/* log.c */
void ssh_log(SSH_SESSION *session, int prioriry, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);

/* session.c */
SSH_SESSION *ssh_new(void);
socket_t ssh_get_fd(SSH_SESSION *session);
int ssh_get_version(SSH_SESSION *session);
int ssh_get_status(SSH_SESSION *session);
const char *ssh_get_disconnect_message(SSH_SESSION *session);
void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options);
void ssh_set_fd_toread(SSH_SESSION *session);
void ssh_set_fd_towrite(SSH_SESSION *session);
void ssh_set_fd_except(SSH_SESSION *session);
void ssh_set_blocking(SSH_SESSION *session, int blocking);
void ssh_silent_disconnect(SSH_SESSION *session);


/* client.c */
int ssh_connect(SSH_SESSION *session);
void ssh_disconnect(SSH_SESSION *session);
int ssh_service_request(SSH_SESSION *session, const char *service);
char *ssh_get_issue_banner(SSH_SESSION *session);
int ssh_get_openssh_version(SSH_SESSION *session);
/* get copyright informations */
const char *ssh_copyright(void);

/* string.h */

/* You can use these functions, they won't change */
/* string_from_char returns a newly allocated string from a char *ptr */
STRING *string_from_char(const char *what);
/* it returns the string len in host byte orders. str->size is big endian warning ! */
size_t string_len(STRING *str);
STRING *string_new(size_t size);
/* string_fill copies the data in the string. */
int string_fill(STRING *str, const void *data, size_t len);
/* returns a newly allocated char array with the str string and a final nul caracter */
char *string_to_char(STRING *str);
STRING *string_copy(STRING *str);
/* burns the data inside a string */
void string_burn(STRING *str);
void *string_data(STRING *str);
void string_free(STRING *str);

/* useful for debug */
char *ssh_get_hexa(const unsigned char *what, size_t len);
void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len);
int ssh_get_random(void *where,int len,int strong);

/* this one can be called by the client to see the hash of the public key before accepting it */
int ssh_get_pubkey_hash(SSH_SESSION *session, unsigned char **hash);
STRING *ssh_get_pubkey(SSH_SESSION *session);

/* in connect.c */
int ssh_fd_poll(SSH_SESSION *session,int *write, int *except);
int ssh_select(CHANNEL **channels, CHANNEL **outchannels, socket_t maxfd,
    fd_set *readfds, struct timeval *timeout);

void publickey_free(PUBLIC_KEY *key);

/* in keyfiles.c */

PRIVATE_KEY *privatekey_from_file(SSH_SESSION *session, const char *filename,
    int type, const char *passphrase);
STRING *publickey_to_string(PUBLIC_KEY *key);
PUBLIC_KEY *publickey_from_privatekey(PRIVATE_KEY *prv);
void privatekey_free(PRIVATE_KEY *prv);
STRING *publickey_from_file(SSH_SESSION *session, const char *filename,
    int *type);
int ssh_is_server_known(SSH_SESSION *session);
int ssh_write_knownhost(SSH_SESSION *session);

/* in channels.c */

CHANNEL *channel_new(SSH_SESSION *session);
int channel_open_forward(CHANNEL *channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
int channel_open_session(CHANNEL *channel);
void channel_free(CHANNEL *channel);
int channel_request_pty(CHANNEL *channel);
int channel_request_pty_size(CHANNEL *channel, const char *term,
    int cols, int rows);
int channel_change_pty_size(CHANNEL *channel,int cols,int rows);
int channel_request_shell(CHANNEL *channel);
int channel_request_subsystem(CHANNEL *channel, const char *system);
int channel_request_env(CHANNEL *channel, const char *name, const char *value);
int channel_request_exec(CHANNEL *channel, const char *cmd);
int channel_request_sftp(CHANNEL *channel);
int channel_write(CHANNEL *channel, const void *data, u32 len);
int channel_send_eof(CHANNEL *channel);
int channel_is_eof(CHANNEL *channel);
int channel_read(CHANNEL *channel, void *dest, u32 count, int is_stderr);
int channel_read_buffer(CHANNEL *channel, BUFFER *buffer, u32 count,
    int is_stderr);
int channel_poll(CHANNEL *channel, int is_stderr);
int channel_close(CHANNEL *channel);
void channel_set_blocking(CHANNEL *channel, int blocking);
int channel_read_nonblocking(CHANNEL *channel, void *dest, u32 count,
    int is_stderr);
int channel_is_open(CHANNEL *channel);
int channel_is_closed(CHANNEL *channel);
int channel_select(CHANNEL **readchans, CHANNEL **writechans, CHANNEL **exceptchans, struct 
        timeval * timeout);
SSH_SESSION *channel_get_session(CHANNEL *channel);
int channel_get_exit_status(CHANNEL *channel);
/* in options.c */

/**
 * @brief SSH authentication callback.
 *
 * @param prompt        Prompt to be displayed.
 * @param buf           Buffer to save the password. You should null-terminate it.
 * @param len           Length of the buffer.
 * @param echo          Enable or disable the echo of what you type.
 * @param verify        Should the password be verified?
 * @param userdata      Userdata to be passed to the callback function. Useful
 *                      for GUI applications.
 *
 * @return              0 on success, < 0 on error.
 */
typedef int (*ssh_auth_callback) (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata);

SSH_OPTIONS *ssh_options_new(void);
SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt);
void ssh_options_free(SSH_OPTIONS *opt);
int ssh_options_set_wanted_algos(SSH_OPTIONS *opt, int algo, const char *list);
int ssh_options_set_username(SSH_OPTIONS *opt, const char *username);
int ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port);
int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv);
int ssh_options_set_host(SSH_OPTIONS *opt, const char *host);
int ssh_options_set_fd(SSH_OPTIONS *opt, socket_t fd);
int ssh_options_set_bind(SSH_OPTIONS *opt, const char *bindaddr, int port);
int ssh_options_set_ssh_dir(SSH_OPTIONS *opt, const char *dir);
int ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, const char *dir);
int ssh_options_set_identity(SSH_OPTIONS *opt, const char *identity);
int ssh_options_set_banner(SSH_OPTIONS *opt, const char *banner);
int ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)
        (void *arg, float status), void *arg);
int ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds, long usec);
int ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow);
int ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow);
int ssh_options_set_log_function(SSH_OPTIONS *opt,
    void (*callback)(const char *message, SSH_SESSION *session, int verbosity));
int ssh_options_set_log_verbosity(SSH_OPTIONS *opt, int verbosity);
int ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, const char *dsakey);
int ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, const char *rsakey);
int ssh_options_set_auth_callback(SSH_OPTIONS *opt, ssh_auth_callback cb,
    void *userdata);


/* buffer.c */

/** creates a new buffer 
 */
BUFFER *buffer_new(void);
void buffer_free(BUFFER *buffer);
/* buffer_get returns a pointer to the begining of the buffer. no position is taken into account */
void *buffer_get(BUFFER *buffer);
/* same here */
u32 buffer_get_len(BUFFER *buffer);


/* in auth.c */
int ssh_auth_list(SSH_SESSION *session);
/* these functions returns AUTH_ERROR is some serious error has happened,
  AUTH_SUCCESS if success,
  AUTH_PARTIAL if partial success,
  AUTH_DENIED if refused */
int ssh_userauth_list(SSH_SESSION *session, const char *username);
int ssh_userauth_none(SSH_SESSION *session, const char *username);
int ssh_userauth_password(SSH_SESSION *session, const char *username, const char *password);
int ssh_userauth_offer_pubkey(SSH_SESSION *session, const char *username, int type, STRING *publickey);
int ssh_userauth_pubkey(SSH_SESSION *session, const char *username, STRING *publickey, PRIVATE_KEY *privatekey);
int ssh_userauth_agent_pubkey(SSH_SESSION *session, const char *username,
    PUBLIC_KEY *publickey);
int ssh_userauth_autopubkey(SSH_SESSION *session, const char *passphrase);
int ssh_userauth_kbdint(SSH_SESSION *session, const char *user, const char *submethods);
int ssh_userauth_kbdint_getnprompts(SSH_SESSION *session);
const char *ssh_userauth_kbdint_getname(SSH_SESSION *session);
const char *ssh_userauth_kbdint_getinstruction(SSH_SESSION *session);
const char *ssh_userauth_kbdint_getprompt(SSH_SESSION *session, unsigned int i, char *echo);
int ssh_userauth_kbdint_setanswer(SSH_SESSION *session, unsigned int i,
    const char *answer);


/* init.c */
int ssh_init(void);
int ssh_finalize(void);

#ifdef __cplusplus
}
#endif
#endif /* _LIBSSH_H */
/* vim: set ts=2 sw=2 et cindent: */
