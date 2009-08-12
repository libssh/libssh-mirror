/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#ifdef LIBSSH_STATIC
  #define LIBSSH_API
#else
  #if defined _WIN32 || defined __CYGWIN__
    #ifdef LIBSSH_EXPORTS
      #ifdef __GNUC__
        #define LIBSSH_API __attribute__((dllexport))
      #else
        #define LIBSSH_API __declspec(dllexport)
      #endif
    #else
      #ifdef __GNUC__
        #define LIBSSH_API __attribute__((dllimport))
      #else
        #define LIBSSH_API __declspec(dllimport)
      #endif
    #endif
  #else
    #if __GNUC__ >= 4
      #define LIBSSH_API __attribute__((visibility("default")))
    #else
      #define LIBSSH_API
    #endif
  #endif
#endif

#ifdef _MSC_VER
  /* Visual Studio hasn't inttypes.h so it doesn't know uint32_t */
  typedef unsigned int uint32_t;
  typedef unsigned short uint16_t;
  typedef unsigned char uint8_t;
  typedef unsigned long long uint64_t;
#else /* _MSC_VER */
  #include <unistd.h>
  #include <inttypes.h>
#endif /* _MSC_VER */

#ifdef _WIN32
  #include <winsock2.h>
#else /* _WIN32 */
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
#define LIBSSH_VERSION_MINOR  4
#define LIBSSH_VERSION_MICRO  0

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

#ifndef SSH_SAFE_NAMESPACE
typedef struct ssh_string_struct STRING;
typedef struct ssh_buffer_struct BUFFER;
typedef struct ssh_public_key_struct PUBLIC_KEY;
typedef struct ssh_private_key_struct PRIVATE_KEY;
typedef struct ssh_channel_struct CHANNEL;
typedef struct ssh_agent_struct AGENT;
#endif

typedef struct ssh_options_struct SSH_OPTIONS;
typedef struct ssh_session_struct SSH_SESSION;
typedef struct ssh_kbdint_struct SSH_KBDINT;

typedef struct ssh_string_struct* ssh_string;
typedef struct ssh_buffer_struct* ssh_buffer;
typedef struct ssh_public_key_struct* ssh_public_key;
typedef struct ssh_private_key_struct* ssh_private_key;
typedef struct ssh_options_struct* ssh_options;
typedef struct ssh_channel_struct* ssh_channel;
typedef struct ssh_agent_struct* ssh_agent;
typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_kbdint_struct* ssh_kbdint;
typedef struct ssh_scp_struct* ssh_scp;

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

/* auth flags */
#define SSH_AUTH_METHOD_UNKNOWN 0
#define SSH_AUTH_METHOD_NONE 0x0001
#define SSH_AUTH_METHOD_PASSWORD 0x0002
#define SSH_AUTH_METHOD_PUBLICKEY 0x0004
#define SSH_AUTH_METHOD_HOSTBASED 0x0008
#define SSH_AUTH_METHOD_INTERACTIVE 0x0010

/* messages */
#define SSH_REQUEST_AUTH 1
#define SSH_REQUEST_CHANNEL_OPEN 2
#define SSH_REQUEST_CHANNEL 3
#define SSH_REQUEST_SERVICE 4
#define SSH_REQUEST_GLOBAL 5

#define SSH_CHANNEL_UNKNOWN 0
#define SSH_CHANNEL_SESSION 1
#define SSH_CHANNEL_DIRECT_TCPIP 2
#define SSH_CHANNEL_FORWARDED_TCPIP 3
#define SSH_CHANNEL_X11 4

#define SSH_CHANNEL_REQUEST_UNKNOWN 0
#define SSH_CHANNEL_REQUEST_PTY 1
#define SSH_CHANNEL_REQUEST_EXEC 2
#define SSH_CHANNEL_REQUEST_SHELL 3
#define SSH_CHANNEL_REQUEST_ENV 4
#define SSH_CHANNEL_REQUEST_SUBSYSTEM 5
#define SSH_CHANNEL_REQUEST_WINDOW_CHANGE 6

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

LIBSSH_API const char *ssh_get_error(void *error); 
LIBSSH_API int ssh_get_error_code(void *error);

/* version checks */
LIBSSH_API const char *ssh_version(int req_version);

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
LIBSSH_API void ssh_log(SSH_SESSION *session, int prioriry, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);

/* session.c */
LIBSSH_API SSH_SESSION *ssh_new(void);
LIBSSH_API socket_t ssh_get_fd(SSH_SESSION *session);
LIBSSH_API int ssh_get_version(SSH_SESSION *session);
LIBSSH_API int ssh_get_status(SSH_SESSION *session);
LIBSSH_API const char *ssh_get_disconnect_message(SSH_SESSION *session);
LIBSSH_API void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options);
LIBSSH_API void ssh_set_fd_toread(SSH_SESSION *session);
LIBSSH_API void ssh_set_fd_towrite(SSH_SESSION *session);
LIBSSH_API void ssh_set_fd_except(SSH_SESSION *session);
LIBSSH_API void ssh_set_blocking(SSH_SESSION *session, int blocking);
LIBSSH_API void ssh_silent_disconnect(SSH_SESSION *session);


/* client.c */
LIBSSH_API int ssh_connect(SSH_SESSION *session);
LIBSSH_API void ssh_disconnect(SSH_SESSION *session);
LIBSSH_API int ssh_service_request(SSH_SESSION *session, const char *service);
LIBSSH_API char *ssh_get_issue_banner(SSH_SESSION *session);
LIBSSH_API int ssh_get_openssh_version(ssh_session session);
/* get copyright informations */
LIBSSH_API const char *ssh_copyright(void);

/* string.h */

/* You can use these functions, they won't change */
/* string_from_char returns a newly allocated string from a char *ptr */
LIBSSH_API ssh_string string_from_char(const char *what);
/* it returns the string len in host byte orders. str->size is big endian warning ! */
LIBSSH_API size_t string_len(ssh_string str);
LIBSSH_API ssh_string string_new(size_t size);
/* string_fill copies the data in the string. */
LIBSSH_API int string_fill(ssh_string str, const void *data, size_t len);
/* returns a newly allocated char array with the str string and a final nul caracter */
LIBSSH_API char *string_to_char(ssh_string str);
LIBSSH_API ssh_string string_copy(ssh_string str);
/* burns the data inside a string */
LIBSSH_API void string_burn(ssh_string str);
LIBSSH_API void *string_data(ssh_string str);
LIBSSH_API void string_free(ssh_string str);

/* useful for debug */
LIBSSH_API char *ssh_get_hexa(const unsigned char *what, size_t len);
LIBSSH_API void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len);
LIBSSH_API int ssh_get_random(void *where,int len,int strong);

/* this one can be called by the client to see the hash of the public key before accepting it */
LIBSSH_API int ssh_get_pubkey_hash(SSH_SESSION *session, unsigned char **hash);
LIBSSH_API void ssh_clean_pubkey_hash(unsigned char **hash);
LIBSSH_API ssh_string ssh_get_pubkey(SSH_SESSION *session);

/* in connect.c */
LIBSSH_API int ssh_select(ssh_channel *channels, ssh_channel *outchannels, socket_t maxfd,
    fd_set *readfds, struct timeval *timeout);

LIBSSH_API void publickey_free(ssh_public_key key);

/* in keyfiles.c */

LIBSSH_API ssh_private_key privatekey_from_file(SSH_SESSION *session, const char *filename,
    int type, const char *passphrase);
LIBSSH_API ssh_string publickey_to_string(ssh_public_key key);
LIBSSH_API ssh_public_key publickey_from_privatekey(ssh_private_key prv);
LIBSSH_API void privatekey_free(ssh_private_key prv);
LIBSSH_API ssh_string publickey_from_file(SSH_SESSION *session, const char *filename,
    int *type);
LIBSSH_API int ssh_is_server_known(SSH_SESSION *session);
LIBSSH_API int ssh_write_knownhost(SSH_SESSION *session);

/* in channels.c */

LIBSSH_API ssh_channel channel_new(SSH_SESSION *session);
LIBSSH_API int channel_open_forward(ssh_channel channel, const char *remotehost,
    int remoteport, const char *sourcehost, int localport);
LIBSSH_API int channel_open_session(ssh_channel channel);
LIBSSH_API void channel_free(ssh_channel channel);
LIBSSH_API int channel_request_pty(ssh_channel channel);
LIBSSH_API int channel_request_pty_size(ssh_channel channel, const char *term,
    int cols, int rows);
LIBSSH_API int channel_change_pty_size(ssh_channel channel,int cols,int rows);
LIBSSH_API int channel_request_shell(ssh_channel channel);
LIBSSH_API int channel_request_subsystem(ssh_channel channel, const char *system);
LIBSSH_API int channel_request_env(ssh_channel channel, const char *name, const char *value);
LIBSSH_API int channel_request_exec(ssh_channel channel, const char *cmd);
LIBSSH_API int channel_request_sftp(ssh_channel channel);
LIBSSH_API int channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
    const char *cookie, int screen_number);
LIBSSH_API ssh_channel channel_accept_x11(ssh_channel channel, int timeout_ms);
LIBSSH_API int channel_write(ssh_channel channel, const void *data, uint32_t len);
LIBSSH_API int channel_send_eof(ssh_channel channel);
LIBSSH_API int channel_is_eof(ssh_channel channel);
LIBSSH_API int channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr);
LIBSSH_API int channel_read_buffer(ssh_channel channel, ssh_buffer buffer, uint32_t count,
    int is_stderr);
LIBSSH_API int channel_poll(ssh_channel channel, int is_stderr);
LIBSSH_API int channel_close(ssh_channel channel);
LIBSSH_API void channel_set_blocking(ssh_channel channel, int blocking);
LIBSSH_API int channel_read_nonblocking(ssh_channel channel, void *dest, uint32_t count,
    int is_stderr);
LIBSSH_API int channel_is_open(ssh_channel channel);
LIBSSH_API int channel_is_closed(ssh_channel channel);
LIBSSH_API int channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, struct
        timeval * timeout);
LIBSSH_API SSH_SESSION *channel_get_session(ssh_channel channel);
LIBSSH_API int channel_get_exit_status(ssh_channel channel);
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

LIBSSH_API SSH_OPTIONS *ssh_options_new(void);
LIBSSH_API SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt);
LIBSSH_API void ssh_options_free(SSH_OPTIONS *opt);
LIBSSH_API int ssh_options_set_wanted_algos(SSH_OPTIONS *opt, int algo, const char *list);
LIBSSH_API int ssh_options_set_username(SSH_OPTIONS *opt, const char *username);
LIBSSH_API int ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port);
LIBSSH_API int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv);
LIBSSH_API int ssh_options_set_host(SSH_OPTIONS *opt, const char *host);
LIBSSH_API int ssh_options_set_fd(SSH_OPTIONS *opt, socket_t fd);
LIBSSH_API int ssh_options_set_bind(SSH_OPTIONS *opt, const char *bindaddr, int port);
LIBSSH_API int ssh_options_set_ssh_dir(SSH_OPTIONS *opt, const char *dir);
LIBSSH_API int ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, const char *dir);
LIBSSH_API int ssh_options_set_identity(SSH_OPTIONS *opt, const char *identity);
LIBSSH_API int ssh_options_set_banner(SSH_OPTIONS *opt, const char *banner);
LIBSSH_API int ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)
        (void *arg, float status), void *arg);
LIBSSH_API int ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds, long usec);
LIBSSH_API int ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow);
LIBSSH_API int ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow);
LIBSSH_API int ssh_options_set_log_function(SSH_OPTIONS *opt,
    void (*callback)(const char *message, SSH_SESSION *session, int verbosity));
LIBSSH_API int ssh_options_set_log_verbosity(SSH_OPTIONS *opt, int verbosity);
LIBSSH_API int ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, const char *dsakey);
LIBSSH_API int ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, const char *rsakey);
LIBSSH_API int ssh_options_set_auth_callback(SSH_OPTIONS *opt, ssh_auth_callback cb,
    void *userdata);


/* buffer.c */

/** creates a new buffer 
 */
LIBSSH_API ssh_buffer buffer_new(void);
LIBSSH_API void buffer_free(ssh_buffer buffer);
/* buffer_get returns a pointer to the begining of the buffer. no position is taken into account */
LIBSSH_API void *buffer_get(ssh_buffer buffer);
/* same here */
/* FIXME should be size_t */
LIBSSH_API uint32_t buffer_get_len(ssh_buffer buffer);


/* in auth.c */
LIBSSH_API int ssh_auth_list(SSH_SESSION *session);
/* these functions returns AUTH_ERROR is some serious error has happened,
  AUTH_SUCCESS if success,
  AUTH_PARTIAL if partial success,
  AUTH_DENIED if refused */
LIBSSH_API int ssh_userauth_list(SSH_SESSION *session, const char *username);
LIBSSH_API int ssh_userauth_none(SSH_SESSION *session, const char *username);
LIBSSH_API int ssh_userauth_password(SSH_SESSION *session, const char *username, const char *password);
LIBSSH_API int ssh_userauth_offer_pubkey(SSH_SESSION *session, const char *username, int type, ssh_string publickey);
LIBSSH_API int ssh_userauth_pubkey(SSH_SESSION *session, const char *username, ssh_string publickey, ssh_private_key privatekey);
#ifndef _WIN32
LIBSSH_API int ssh_userauth_agent_pubkey(SSH_SESSION *session, const char *username,
    ssh_public_key publickey);
#endif
LIBSSH_API int ssh_userauth_autopubkey(SSH_SESSION *session, const char *passphrase);
LIBSSH_API int ssh_userauth_kbdint(SSH_SESSION *session, const char *user, const char *submethods);
LIBSSH_API int ssh_userauth_kbdint_getnprompts(SSH_SESSION *session);
LIBSSH_API const char *ssh_userauth_kbdint_getname(SSH_SESSION *session);
LIBSSH_API const char *ssh_userauth_kbdint_getinstruction(SSH_SESSION *session);
LIBSSH_API const char *ssh_userauth_kbdint_getprompt(SSH_SESSION *session, unsigned int i, char *echo);
LIBSSH_API int ssh_userauth_kbdint_setanswer(SSH_SESSION *session, unsigned int i,
    const char *answer);

/* init.c */
LIBSSH_API int ssh_init(void);
LIBSSH_API int ssh_finalize(void);

/* messages.c */
typedef struct ssh_message SSH_MESSAGE;

LIBSSH_API SSH_MESSAGE *ssh_message_retrieve(SSH_SESSION *session, uint32_t packettype);
LIBSSH_API SSH_MESSAGE *ssh_message_get(SSH_SESSION *session);
LIBSSH_API int ssh_message_type(SSH_MESSAGE *msg);
LIBSSH_API int ssh_message_subtype(SSH_MESSAGE *msg);
LIBSSH_API void ssh_message_free(SSH_MESSAGE *msg);

LIBSSH_API ssh_channel ssh_message_channel_request_open_reply_accept(SSH_MESSAGE *msg);
LIBSSH_API int ssh_message_channel_request_reply_success(SSH_MESSAGE *msg);

/* scp.c */
enum {
  /** Code is going to write/create remote files */
  SSH_SCP_WRITE,
  /** Code is going to read remote files */
  SSH_SCP_READ
};

LIBSSH_API ssh_scp ssh_scp_new(ssh_session session, int mode, const char *location);
LIBSSH_API int ssh_scp_init(ssh_scp scp);
LIBSSH_API int ssh_scp_close(ssh_scp scp);
LIBSSH_API void ssh_scp_free(ssh_scp scp);
LIBSSH_API int ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, const char *perms);
LIBSSH_API int ssh_scp_write(ssh_scp scp, const void *buffer, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* _LIBSSH_H */
/* vim: set ts=2 sw=2 et cindent: */
