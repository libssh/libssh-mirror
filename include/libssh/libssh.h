/*
Copyright 2003,04 Aris Adamantiadis

This file is part of the SSH Library

The SSH Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The SSH Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the SSH Library; see the file COPYING.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

#ifndef _LIBSSH_H
#define _LIBSSH_H
#include <unistd.h>
#include <sys/select.h> /* for fd_set * */
#include <inttypes.h>

#define LIBSSH_VERSION "libssh-0.2"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct string_struct STRING;
typedef struct buffer_struct BUFFER;
typedef struct public_key_struct PUBLIC_KEY;
typedef struct private_key_struct PRIVATE_KEY;
typedef struct ssh_options_struct SSH_OPTIONS;
typedef struct channel_struct CHANNEL;
typedef struct ssh_session SSH_SESSION;
typedef struct ssh_kbdint SSH_KBDINT;

/* integer values */
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
typedef uint8_t u8;

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

/* status flags */

#define SSH_CLOSED (1<<0)
#define SSH_READ_PENDING (1<<1)
#define SSH_CLOSED_ERROR (1<<2)

#define SSH_SERVER_ERROR -1
#define SSH_SERVER_NOT_KNOWN 0
#define SSH_SERVER_KNOWN_OK 1
#define SSH_SERVER_KNOWN_CHANGED 2
#define SSH_SERVER_FOUND_OTHER 3

#ifndef MD5_DIGEST_LEN
    #define MD5_DIGEST_LEN 16
#endif
/* errors */

#define SSH_NO_ERROR 0
#define SSH_REQUEST_DENIED 1
#define SSH_FATAL 2
#define SSH_EINTR 3

/* error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* error of some kind */
#define SSH_AGAIN 1  /* the nonblocking call must be repeated */

char *ssh_get_error(void *error); 
int ssh_get_error_code(void *error);
void ssh_say(int priority,char *format,...);
void ssh_set_verbosity(int num);

 /* There is a verbosity level */
 /* 3 : packet level */
 /* 2 : protocol level */
 /* 1 : functions level */
 /* 0 : important messages only */
 /* -1 : no messages */

/* session.c */
SSH_SESSION *ssh_new();
void ssh_set_options(SSH_SESSION *session, SSH_OPTIONS *options);
int ssh_get_fd(SSH_SESSION *session);
void ssh_silent_disconnect(SSH_SESSION *session);
int ssh_get_version(SSH_SESSION *session);
void ssh_set_fd_toread(SSH_SESSION *session);
void ssh_set_fd_towrite(SSH_SESSION *session);
void ssh_set_fd_except(SSH_SESSION *session);


/* client.c */
int ssh_connect(SSH_SESSION *session);
void ssh_disconnect(SSH_SESSION *session);
int ssh_service_request(SSH_SESSION *session,char *service);
char *ssh_get_issue_banner(SSH_SESSION *session);
/* get copyright informations */
const char *ssh_copyright();
/* string.h */

/* You can use these functions, they won't change */
/* makestring returns a newly allocated string from a char * ptr */
STRING *string_from_char(char *what);
/* it returns the string len in host byte orders. str->size is big endian warning ! */
int string_len(STRING *str);
STRING *string_new(unsigned int size);
/* string_fill copies the data in the string. it does NOT check for boundary so allocate enough place with string_new */
void string_fill(STRING *str,void *data,int len);
/* returns a newly allocated char array with the str string and a final nul caracter */
char *string_to_char(STRING *str);
STRING *string_copy(STRING *str);
/* burns the data inside a string */
void string_burn(STRING *str);
void *string_data(STRING *str);

/* deprecated */
void ssh_crypto_init();

/* useful for debug */
void ssh_print_hexa(char *descr,unsigned char *what, int len);
int ssh_get_random(void *where,int len,int strong);

/* this one can be called by the client to see the hash of the public key before accepting it */
int ssh_get_pubkey_hash(SSH_SESSION *session,unsigned char hash[MD5_DIGEST_LEN]);
STRING *ssh_get_pubkey(SSH_SESSION *session);

/* in connect.c */
int ssh_fd_poll(SSH_SESSION *session,int *write, int *except);
int ssh_select(CHANNEL **channels,CHANNEL **outchannels, int maxfd, fd_set *readfds, struct timeval *timeout);

void publickey_free(PUBLIC_KEY *key);

/* in keyfiles.c */

PRIVATE_KEY *privatekey_from_file(SSH_SESSION *session,char *filename,int type,char *passphrase);
STRING *publickey_to_string(PUBLIC_KEY *key);
PUBLIC_KEY *publickey_from_privatekey(PRIVATE_KEY *prv);
void private_key_free(PRIVATE_KEY *prv);
STRING *publickey_from_file(SSH_SESSION *session, char *filename,int *_type);
STRING *publickey_from_next_file(SSH_SESSION *session,char **pub_keys_path,char **keys_path,
                            char **privkeyfile,int *type,int *count);
int ssh_is_server_known(SSH_SESSION *session);
int ssh_write_knownhost(SSH_SESSION *session);

/* in channels.c */

CHANNEL *channel_new(SSH_SESSION *session);
int channel_open_forward(CHANNEL *channel,char *remotehost, int remoteport, char *sourcehost, int localport);
int channel_open_session(CHANNEL *channel);
void channel_free(CHANNEL *channel);
int channel_request_pty(CHANNEL *channel);
int channel_request_pty_size(CHANNEL *channel, char *term,int cols, int rows);
int channel_change_pty_size(CHANNEL *channel,int cols,int rows);
int channel_request_shell(CHANNEL *channel);
int channel_request_subsystem(CHANNEL *channel, char *system);
int channel_request_env(CHANNEL *channel,char *name, char *value);
int channel_request_exec(CHANNEL *channel, char *cmd);
int channel_request_sftp(CHANNEL *channel);
int channel_write(CHANNEL *channel,void *data,int len);
int channel_send_eof(CHANNEL *channel);
int channel_read(CHANNEL *channel, BUFFER *buffer,int bytes,int is_stderr);
int channel_poll(CHANNEL *channel, int is_stderr);
int channel_close(CHANNEL *channel);
int channel_read_nonblocking(CHANNEL *channel, char *dest, int len, int is_stderr);
int channel_is_open(CHANNEL *channel);
int channel_is_closed(CHANNEL *channel);
int channel_select(CHANNEL **readchans, CHANNEL **writechans, CHANNEL **exceptchans, struct 
        timeval * timeout);
/* in options.c */

SSH_OPTIONS *ssh_options_new();
SSH_OPTIONS *ssh_options_copy(SSH_OPTIONS *opt);
int ssh_options_set_wanted_algos(SSH_OPTIONS *opt,int algo, char *list);
void ssh_options_set_username(SSH_OPTIONS *opt,char *username);
void ssh_options_set_port(SSH_OPTIONS *opt, unsigned int port);
int ssh_options_getopt(SSH_OPTIONS *options, int *argcptr, char **argv);
void ssh_options_set_host(SSH_OPTIONS *opt, const char *host);
void ssh_options_set_fd(SSH_OPTIONS *opt, int fd);
void ssh_options_set_bind(SSH_OPTIONS *opt, char *bindaddr,int port);
void ssh_options_set_identity(SSH_OPTIONS *opt, char *identity);
void ssh_options_set_status_callback(SSH_OPTIONS *opt, void (*callback)
        (void *arg, float status), void *arg);
void ssh_options_set_timeout(SSH_OPTIONS *opt, long seconds, long usec);
void ssh_options_set_ssh_dir(SSH_OPTIONS *opt, char *dir);
void ssh_options_set_known_hosts_file(SSH_OPTIONS *opt, char *dir);
void ssh_options_allow_ssh1(SSH_OPTIONS *opt, int allow);
void ssh_options_allow_ssh2(SSH_OPTIONS *opt, int allow);
void ssh_options_set_dsa_server_key(SSH_OPTIONS *opt, char *dsakey);
void ssh_options_set_rsa_server_key(SSH_OPTIONS *opt, char *rsakey);


/* buffer.c */

/** creates a new buffer 
 */
BUFFER *buffer_new();
void buffer_free(BUFFER *buffer);
/* buffer_get returns a pointer to the begining of the buffer. no position is taken into account */
void *buffer_get(BUFFER *buffer);
/* same here */
int buffer_get_len(BUFFER *buffer);


/* in auth.c */
/* these functions returns AUTH_ERROR is some serious error has happened,
  AUTH_SUCCESS if success,
  AUTH_PARTIAL if partial success,
  AUTH_DENIED if refused */
int ssh_userauth_none(SSH_SESSION *session,char *username);
int ssh_userauth_password(SSH_SESSION *session,char *username,char *password);
int ssh_userauth_offer_pubkey(SSH_SESSION *session, char *username,int type, STRING *publickey);
int ssh_userauth_pubkey(SSH_SESSION *session, char *username, STRING *publickey, PRIVATE_KEY *privatekey);
int ssh_userauth_autopubkey(SSH_SESSION *session);
int ssh_userauth_kbdint(SSH_SESSION *session, char *user, char *submethods);
int ssh_userauth_kbdint_getnprompts(SSH_SESSION *session);
char *ssh_userauth_kbdint_getname(SSH_SESSION *session);
char *ssh_userauth_kbdint_getinstruction(SSH_SESSION *session);
char *ssh_userauth_kbdint_getprompt(SSH_SESSION *session, int i, char *echo);
void ssh_userauth_kbdint_setanswer(SSH_SESSION *session, unsigned int i, char *answer);


/* init.c */
int ssh_finalize();
#ifdef __cplusplus
} ;
#endif
#endif /* _LIBSSH_H */
