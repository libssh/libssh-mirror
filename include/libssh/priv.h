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

/*
 * priv.h file
 * This include file contains everything you shouldn't deal with in
 * user programs. Consider that anything in this file might change
 * without notice; libssh.h file will keep backward compatibility
 * on binary & source
 */

#ifndef _LIBSSH_PRIV_H
#define _LIBSSH_PRIV_H
#include "config.h"
#include "libssh/libssh.h"

/* Debugging constants */

/* Define this if you want to debug crypto systems */
/* it's usefull when you are debugging the lib */
/*#define DEBUG_CRYPTO */

/* some constants */
#define MAX_PACKET_LEN 262144
#define ERROR_BUFFERLEN 1024
#define CLIENTBANNER1 "SSH-1.5-libssh-" SSH_STRINGIFY(LIBSSH_VERSION)
#define CLIENTBANNER2 "SSH-2.0-libssh-" SSH_STRINGIFY(LIBSSH_VERSION)
#define KBDINT_MAX_PROMPT 256 /* more than openssh's :) */
/* some types for public keys */
#define TYPE_DSS 1
#define TYPE_RSA 2
#define TYPE_RSA1 3

/* profiling constants. Don't touch them unless you know what you do */
#ifdef HAVE_LIBCRYPTO
#define OPENSSL_BIGNUMS
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* wrapper things */
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
typedef gcry_md_hd_t SHACTX;
typedef gcry_md_hd_t MD5CTX;
typedef gcry_md_hd_t HMACCTX;
#ifdef MD5_DIGEST_LEN
    #undef MD5_DIGEST_LEN
#endif
#define SHA_DIGEST_LEN 20
#define MD5_DIGEST_LEN 16
#define EVP_MAX_MD_SIZE 36

typedef gcry_mpi_t bignum;

#define bignum_new() gcry_mpi_new(0)
#define bignum_free(num) gcry_mpi_release(num)
#define bignum_set_word(bn,n) gcry_mpi_set_ui(bn,n)
#define bignum_bin2bn(bn,datalen,data) gcry_mpi_scan(data,GCRYMPI_FMT_USG,bn,datalen,NULL)
#define bignum_bn2dec(num) my_gcry_bn2dec(num)
#define bignum_dec2bn(num, data) my_gcry_dec2bn(data, num)
#define bignum_bn2hex(num,data) gcry_mpi_aprint(GCRYMPI_FMT_HEX,data,NULL,num)
#define bignum_hex2bn(num,datalen,data) gcry_mpi_scan(num,GCRYMPI_FMT_HEX,data,datalen,NULL)
#define bignum_rand(num,bits) gcry_mpi_randomize(num,bits,GCRY_STRONG_RANDOM),gcry_mpi_set_bit(num,bits-1),gcry_mpi_set_bit(num,0)
#define bignum_mod_exp(dest,generator,exp,modulo) gcry_mpi_powm(dest,generator,exp,modulo)
#define bignum_num_bits(num) gcry_mpi_get_nbits(num)
#define bignum_num_bytes(num) ((gcry_mpi_get_nbits(num)+7)/8)
#define bignum_is_bit_set(num,bit) gcry_mpi_test_bit(num,bit)
#define bignum_bn2bin(num,datalen,data) gcry_mpi_print(GCRYMPI_FMT_USG,data,datalen,NULL,num)
#define bignum_cmp(num1,num2) gcry_mpi_cmp(num1,num2)

#elif defined HAVE_LIBCRYPTO
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
typedef SHA_CTX* SHACTX;
typedef MD5_CTX*  MD5CTX;
typedef HMAC_CTX* HMACCTX;
#ifdef MD5_DIGEST_LEN
    #undef MD5_DIGEST_LEN
#endif
#define SHA_DIGEST_LEN SHA_DIGEST_LENGTH
#define MD5_DIGEST_LEN MD5_DIGEST_LENGTH

#endif /* OPENSSL_CRYPTO */
#ifdef OPENSSL_BIGNUMS
#include <openssl/bn.h>
typedef BIGNUM*  bignum;
typedef BN_CTX* bignum_CTX;

#define bignum_new() BN_new()
#define bignum_free(num) BN_clear_free(num)
#define bignum_set_word(bn,n) BN_set_word(bn,n)
#define bignum_bin2bn(bn,datalen,data) BN_bin2bn(bn,datalen,data)
#define bignum_bn2dec(num) BN_bn2dec(num)
#define bignum_dec2bn(bn,data) BN_dec2bn(data,bn)
#define bignum_bn2hex(num) BN_bn2hex(num)
#define bignum_rand(rnd, bits, top, bottom) BN_rand(rnd,bits,top,bottom)
#define bignum_ctx_new() BN_CTX_new()
#define bignum_ctx_free(num) BN_CTX_free(num)
#define bignum_mod_exp(dest,generator,exp,modulo,ctx) BN_mod_exp(dest,generator,exp,modulo,ctx)
#define bignum_num_bytes(num) BN_num_bytes(num)
#define bignum_num_bits(num) BN_num_bits(num)
#define bignum_is_bit_set(num,bit) BN_is_bit_set(num,bit)
#define bignum_bn2bin(num,ptr) BN_bn2bin(num,ptr)
#define bignum_cmp(num1,num2) BN_cmp(num1,num2)

#endif /* OPENSSL_BIGNUMS */

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* poll support */
#ifdef HAVE_POLL
#include <poll.h>
typedef struct pollfd pollfd_t;
#else /* HAVE_POLL */
typedef struct pollfd_s {
  socket_t fd;      /* file descriptor */
  short events;     /* requested events */
  short revents;    /* returned events */
} pollfd_t;

#define POLLIN    0x001  /* There is data to read.  */
#define POLLPRI   0x002  /* There is urgent data to read.  */
#define POLLOUT   0x004  /* Writing now will not block.  */

#define POLLERR   0x008  /* Error condition.  */
#define POLLHUP   0x010  /* Hung up.  */
#define POLLNVAL  0x020  /* Invalid polling request.  */

typedef unsigned long int nfds_t;
#endif /* HAVE_POLL */

/* wrapper.c */
MD5CTX md5_init(void);
void md5_update(MD5CTX c, const void *data, unsigned long len);
void md5_final(unsigned char *md,MD5CTX c);
SHACTX sha1_init(void);
void sha1_update(SHACTX c, const void *data, unsigned long len);
void sha1_final(unsigned char *md,SHACTX c);
void sha1(unsigned char *digest,int len,unsigned char *hash);
#define HMAC_SHA1 1
#define HMAC_MD5 2
HMACCTX hmac_init(const void *key,int len,int type);
void hmac_update(HMACCTX c, const void *data, unsigned long len);
void hmac_final(HMACCTX ctx,unsigned char *hashmacbuf,unsigned int *len);

/* strings and buffers */
/* must be 32 bits number + immediatly our data */
struct string_struct {
	u32 size;
	unsigned char string[MAX_PACKET_LEN];
} __attribute__ ((packed));

/** Describes a buffer state at a moment
 */
struct buffer_struct {
    char *data;
    u32 used;
    u32 allocated;
    u32 pos;
};

/* i should remove it one day */
typedef struct packet_struct {
	int valid;
	u32 len;
	u8 type;
} PACKET;

typedef struct kex_struct {
	unsigned char cookie[16];
	char **methods;
} KEX;

struct public_key_struct {
    int type;
    const char *type_c; /* Don't free it ! it is static */
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_pub;
    gcry_sexp_t rsa_pub;
#elif HAVE_LIBCRYPTO
    DSA *dsa_pub;
    RSA *rsa_pub;
#endif
};

struct private_key_struct {
    int type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_priv;
    gcry_sexp_t rsa_priv;
#elif defined HAVE_LIBCRYPTO
    DSA *dsa_priv;
    RSA *rsa_priv;
#endif
};

typedef struct signature_struct {
    int type;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_sign;
    gcry_sexp_t rsa_sign;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *dsa_sign;
    STRING *rsa_sign;
#endif
} SIGNATURE;


struct error_struct {
/* error handling */
    int error_code;
    char error_buffer[ERROR_BUFFERLEN];
};

struct ssh_options_struct {
    struct error_struct error;
    char *banner; /* explicit banner to send */
    char *username;
    char *host;
    char *bindaddr;
    int bindport;
    char *identity;
    char *ssh_dir;
    char *known_hosts_file;
    socket_t fd; /* specificaly wanted file descriptor, don't connect host */
    int port;
    int dont_verify_hostkey; /* Don't spare time, don't check host key ! unneeded to say it's dangerous and not safe */
    int use_nonexisting_algo; /* if user sets a not supported algorithm for kex, don't complain */
    char *wanted_methods[10]; /* the kex methods can be choosed. better use the kex fonctions to do that */
    void *wanted_cookie; /* wants a specific cookie to be sent ? if null, generate a new one */
    ssh_auth_callback auth_function; /* this functions will be called if e.g. a keyphrase is needed. */
    void *auth_userdata;
    void (*connect_status_function)(void *arg, float status); /* status callback function */
    void *connect_status_arg; /* arbitrary argument */
    long timeout; /* seconds */
    long timeout_usec;
    int ssh2allowed;
    int ssh1allowed;
    char *dsakey;
    char *rsakey; /* host key for server implementation */
    int log_verbosity;
    void (*log_function)(const char *message, SSH_SESSION *session, int verbosity); //log callback
};

typedef struct ssh_crypto_struct {
    bignum e,f,x,k,y;
    unsigned char session_id[SHA_DIGEST_LEN];

    unsigned char encryptIV[SHA_DIGEST_LEN*2];
    unsigned char decryptIV[SHA_DIGEST_LEN*2];

    unsigned char decryptkey[SHA_DIGEST_LEN*2];
    unsigned char encryptkey[SHA_DIGEST_LEN*2];

    unsigned char encryptMAC[SHA_DIGEST_LEN];
    unsigned char decryptMAC[SHA_DIGEST_LEN];
    unsigned char hmacbuf[EVP_MAX_MD_SIZE];
    struct crypto_struct *in_cipher, *out_cipher; /* the cipher structures/objects */
    STRING *server_pubkey;
    const char *server_pubkey_type;
    int do_compress_out; /* idem */
    int do_compress_in; /* don't set them, set the option instead */
    void *compress_out_ctx; /* don't touch it */
    void *compress_in_ctx; /* really, don't */
} CRYPTO;

struct channel_struct {
    struct channel_struct *prev;
    struct channel_struct *next;
    SSH_SESSION *session; /* SSH_SESSION pointer */
    u32 local_channel;
    u32 local_window;
    int local_eof;
    u32 local_maxpacket;

    u32 remote_channel;
    u32 remote_window;
    int remote_eof; /* end of file received */
    u32 remote_maxpacket;
    int open; /* shows if the channel is still opened */
    int delayed_close;
    BUFFER *stdout_buffer;
    BUFFER *stderr_buffer;
    void *userarg;
    int version;
    int blocking;
    int exit_status;
};

struct agent_struct {
  struct socket *sock;
  BUFFER *ident;
  unsigned int count;
};

struct keys_struct {
  const char *privatekey;
  const char *publickey;
};

struct ssh_session {
    struct error_struct error;
    struct socket *socket;
    SSH_OPTIONS *options;
    char *serverbanner;
    char *clientbanner;
    int protoversion;
    int server;
    int client;
    u32 send_seq;
    u32 recv_seq;
/* status flags */
    int closed;
    int closed_by_except;

    int connected;
    /* !=0 when the user got a session handle */
    int alive;
    /* two previous are deprecated */
    int auth_service_asked;

/* socket status */
    int blocking; // functions should block

    STRING *banner; /* that's the issue banner from
                       the server */
    char *remotebanner; /* that's the SSH- banner from
                           remote host. */
    char *discon_msg; /* disconnect message from
                         the remote host */
    BUFFER *in_buffer;
    PACKET in_packet;
    BUFFER *out_buffer;

    /* the states are used by the nonblocking stuff to remember */
    /* where it was before being interrupted */
    int packet_state;
    int dh_handshake_state;
    STRING *dh_server_signature; //information used by dh_handshake.

    KEX server_kex;
    KEX client_kex;
    BUFFER *in_hashbuf;
    BUFFER *out_hashbuf;
    CRYPTO *current_crypto;
    CRYPTO *next_crypto;  /* next_crypto is going to be used after a SSH2_MSG_NEWKEYS */

    CHANNEL *channels; /* linked list of channels */
    int maxchannel;
    int exec_channel_opened; /* version 1 only. more
                                info in channels1.c */
    AGENT *agent; /* ssh agent */

/* keyb interactive data */
    struct ssh_kbdint *kbdint;
    int version; /* 1 or 2 */
    /* server host keys */
    PRIVATE_KEY *rsa_key;
    PRIVATE_KEY *dsa_key;
    /* auths accepted by server */
    int auth_methods;
    int hostkeys; /* contains type of host key wanted by client, in server impl */
    struct ssh_message *ssh_message; /* ssh message */
    int log_verbosity; /*cached copy of the option structure */
    int log_indent; /* indentation level in enter_function logs */
};

struct ssh_kbdint {
    u32 nprompts;
    char *name;
    char *instruction;
    char **prompts;
    unsigned char *echo; /* bool array */
    char **answers;
};

/* server data */

struct ssh_bind_struct {
    struct error_struct error;
    socket_t bindfd;
    SSH_OPTIONS *options;
    int blocking;
    int toaccept;
};

struct ssh_auth_request {
    char *username;
    int method;
    char *password;
};

struct ssh_channel_request_open {
    int type;
    u32 sender;
    u32 window;
    u32 packet_size;
    char *originator;
    u16 orignator_port;
    char *destination;
    u16 destination_port;
};

struct ssh_channel_request {
    int type;
    CHANNEL *channel;
    u8 want_reply;
    /* pty-req type specifics */
    char *TERM;
    u32 width;
    u32 height;
    u32 pxwidth;
    u32 pxheight;
    STRING *modes;

    /* env type request */
    char *var_name;
    char *var_value;
    /* exec type request */
    char *command;
    /* subsystem */
    char *subsystem;
};

struct ssh_message {
    SSH_SESSION *session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
};

#ifndef _WIN32
/* agent.c */
/**
 * @brief Create a new ssh agent structure.
 *
 * @return An allocated ssh agent structure or NULL on error.
 */
struct agent_struct *agent_new(struct ssh_session *session);

void agent_close(struct agent_struct *agent);

/**
 * @brief Free an allocated ssh agent structure.
 *
 * @param agent The ssh agent structure to free.
 */
void agent_free(struct agent_struct *agent);

/**
 * @brief Check if the ssh agent is running.
 *
 * @param session The ssh session to check for the agent.
 *
 * @return 1 if it is running, 0 if not.
 */
int agent_is_running(struct ssh_session *session);

int agent_get_ident_count(struct ssh_session *session);

struct public_key_struct *agent_get_next_ident(struct ssh_session *session,
    char **comment);

struct public_key_struct *agent_get_first_ident(struct ssh_session *session,
    char **comment);

STRING *agent_sign_data(struct ssh_session *session,
    struct buffer_struct *data,
    struct public_key_struct *pubkey);
#endif

/* poll.c */
int ssh_poll(pollfd_t *fds, nfds_t nfds, int timeout);

/* socket.c */

struct socket;
int ssh_socket_init(void);
struct socket *ssh_socket_new(SSH_SESSION *session);
void ssh_socket_free(struct socket *s);
void ssh_socket_set_fd(struct socket *s, socket_t fd);
socket_t ssh_socket_get_fd(struct socket *s);
#ifndef _WIN32
int ssh_socket_unix(struct socket *s, const char *path);
#endif
void ssh_socket_close(struct socket *s);
int ssh_socket_read(struct socket *s, void *buffer, int len);
int ssh_socket_write(struct socket *s,const void *buffer, int len);
int ssh_socket_is_open(struct socket *s);
int ssh_socket_fd_isset(struct socket *s, fd_set *set);
void ssh_socket_fd_set(struct socket *s, fd_set *set, int *fd_max);
int ssh_socket_completeread(struct socket *s, void *buffer, u32 len);
int ssh_socket_completewrite(struct socket *s, const void *buffer, u32 len);
int ssh_socket_wait_for_data(struct socket *s, SSH_SESSION *session, u32 len);
int ssh_socket_nonblocking_flush(struct socket *s);
int ssh_socket_blocking_flush(struct socket *s);
int ssh_socket_poll(struct socket *s, int *writeable, int *except);
void ssh_socket_set_towrite(struct socket *s);
void ssh_socket_set_toread(struct socket *s);
void ssh_socket_set_except(struct socket *s);
int ssh_socket_get_status(struct socket *s);
int ssh_socket_data_available(struct socket *s);
int ssh_socket_data_writable(struct socket *s);
/* session.c */

void ssh_cleanup(SSH_SESSION *session);

/* client.c */

int ssh_send_banner(SSH_SESSION *session, int is_server);
char *ssh_get_banner(SSH_SESSION *session);

/* errors.c */
void ssh_set_error(void *error, int code, const char *descr, ...) PRINTF_ATTRIBUTE(3, 4);

/* in dh.c */
/* DH key generation */
void ssh_print_bignum(const char *which,bignum num);
int dh_generate_e(SSH_SESSION *session);
int dh_generate_f(SSH_SESSION *session);
int dh_generate_x(SSH_SESSION *session);
int dh_generate_y(SSH_SESSION *session);

int ssh_crypto_init(void);
void ssh_crypto_finalize(void);

STRING *dh_get_e(SSH_SESSION *session);
STRING *dh_get_f(SSH_SESSION *session);
int dh_import_f(SSH_SESSION *session,STRING *f_string);
int dh_import_e(SSH_SESSION *session, STRING *e_string);
void dh_import_pubkey(SSH_SESSION *session,STRING *pubkey_string);
int dh_build_k(SSH_SESSION *session);
int make_sessionid(SSH_SESSION *session);
/* add data for the final cookie */
int hashbufin_add_cookie(SSH_SESSION *session, unsigned char *cookie);
int hashbufout_add_cookie(SSH_SESSION *session);
int generate_session_keys(SSH_SESSION *session);
/* returns 1 if server signature ok, 0 otherwise. The NEXT crypto is checked, not the current one */
int signature_verify(SSH_SESSION *session,STRING *signature);
bignum make_string_bn(STRING *string);
STRING *make_bignum_string(bignum num);

/* in crypt.c */
u32 packet_decrypt_len(SSH_SESSION *session,char *crypted);
int packet_decrypt(SSH_SESSION *session, void *packet,unsigned int len);
unsigned char *packet_encrypt(SSH_SESSION *session,void *packet,unsigned int len);
 /* it returns the hmac buffer if exists*/
int packet_hmac_verify(SSH_SESSION *session,BUFFER *buffer,unsigned char *mac);

/* in packet.c */

void packet_parse(SSH_SESSION *session);
int packet_send(SSH_SESSION *session);

int packet_read(SSH_SESSION *session);
int packet_translate(SSH_SESSION *session);
int packet_wait(SSH_SESSION *session,int type,int blocking);
int packet_flush(SSH_SESSION *session, int enforce_blocking);
/* connect.c */
SSH_SESSION *ssh_session_new();
socket_t ssh_connect_host(SSH_SESSION *session, const char *host,const char
        *bind_addr, int port, long timeout, long usec);

/* in kex.c */
extern const char *ssh_kex_nums[];
int ssh_send_kex(SSH_SESSION *session, int server_kex);
void ssh_list_kex(SSH_SESSION *session, KEX *kex);
int set_kex(SSH_SESSION *session);
int ssh_get_kex(SSH_SESSION *session, int server_kex);
int verify_existing_algo(int algo, const char *name);
char **space_tokenize(const char *chain);
int ssh_get_kex1(SSH_SESSION *session);
char *ssh_find_matching(const char *in_d, const char *what_d);

/* in keyfiles.c */

PRIVATE_KEY *_privatekey_from_file(void *session, const char *filename,
    int type);

/* in keys.c */
const char *ssh_type_to_char(int type);
int ssh_type_from_name(const char *name);

PRIVATE_KEY *privatekey_make_dss(SSH_SESSION *session, BUFFER *buffer);
PRIVATE_KEY *privatekey_make_rsa(SSH_SESSION *session, BUFFER *buffer,
    const char *type);
PRIVATE_KEY *privatekey_from_string(SSH_SESSION *session, STRING *privkey_s);

PUBLIC_KEY *publickey_make_dss(SSH_SESSION *session, BUFFER *buffer);
PUBLIC_KEY *publickey_make_rsa(SSH_SESSION *session, BUFFER *buffer, int type);
PUBLIC_KEY *publickey_from_string(SSH_SESSION *session, STRING *pubkey_s);
SIGNATURE *signature_from_string(SSH_SESSION *session, STRING *signature,PUBLIC_KEY *pubkey,int needed_type);
void signature_free(SIGNATURE *sign);
STRING *ssh_do_sign_with_agent(struct ssh_session *session,
    struct buffer_struct *buf, struct public_key_struct *publickey);
STRING *ssh_do_sign(SSH_SESSION *session,BUFFER *sigbuf,
        PRIVATE_KEY *privatekey);
STRING *ssh_sign_session_id(SSH_SESSION *session, PRIVATE_KEY *privatekey);
STRING *ssh_encrypt_rsa1(SSH_SESSION *session, STRING *data, PUBLIC_KEY *key);
/* channel.c */
void channel_handle(SSH_SESSION *session, int type);
CHANNEL *channel_new(SSH_SESSION *session);
int channel_default_bufferize(CHANNEL *channel, void *data, int len,
        int is_stderr);
u32 ssh_channel_new_id(SSH_SESSION *session);
CHANNEL *ssh_channel_from_local(SSH_SESSION *session, u32 id);

/* options.c */

/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(SSH_OPTIONS *opt);
int ssh_options_default_ssh_dir(SSH_OPTIONS *opt);
int ssh_options_default_known_hosts_file(SSH_OPTIONS *opt);

/* buffer.c */
int buffer_add_ssh_string(BUFFER *buffer, STRING *string);
int buffer_add_u8(BUFFER *buffer, u8 data);
int buffer_add_u32(BUFFER *buffer, u32 data);
int buffer_add_u64(BUFFER *buffer, u64 data);
int buffer_add_data(BUFFER *buffer, const void *data, u32 len);
int buffer_prepend_data(BUFFER *buffer, const void *data, u32 len);
int buffer_add_buffer(BUFFER *buffer, BUFFER *source);
int buffer_reinit(BUFFER *buffer);

/* buffer_get_rest returns a pointer to the current position into the buffer */
void *buffer_get_rest(BUFFER *buffer);
/* buffer_get_rest_len returns the number of bytes which can be read */
u32 buffer_get_rest_len(BUFFER *buffer);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
int buffer_get_u8(BUFFER *buffer, u8 *data);
int buffer_get_u32(BUFFER *buffer, u32 *data);
int buffer_get_u64(BUFFER *buffer, u64 *data);

u32 buffer_get_data(BUFFER *buffer, void *data, u32 requestedlen);
/* buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
STRING *buffer_get_ssh_string(BUFFER *buffer);
/* gets a string out of a SSH-1 mpint */
STRING *buffer_get_mpint(BUFFER *buffer);
/* buffer_pass_bytes acts as if len bytes have been read (used for padding) */
u32 buffer_pass_bytes_end(BUFFER *buffer, u32 len);
u32 buffer_pass_bytes(BUFFER *buffer, u32 len);

/* in base64.c */
BUFFER *base64_to_bin(const char *source);
unsigned char *bin_to_base64(const unsigned char *source, int len);

/* gzip.c */
int compress_buffer(SSH_SESSION *session,BUFFER *buf);
int decompress_buffer(SSH_SESSION *session,BUFFER *buf);

/* wrapper.c */
int crypt_set_algorithms(SSH_SESSION *);
int crypt_set_algorithms_server(SSH_SESSION *session);
CRYPTO *crypto_new(void);
void crypto_free(CRYPTO *crypto);

/* crc32.c */
u32 ssh_crc32(const char *buf, u32 len);

/* auth1.c */
int ssh_userauth1_none(SSH_SESSION *session, const char *username);
int ssh_userauth1_offer_pubkey(SSH_SESSION *session, const char *username,
        int type, STRING *pubkey);
int ssh_userauth1_password(SSH_SESSION *session, const char *username,
        const char *password);
/* in misc.c */
/* gets the user home dir. */
char *ssh_get_user_home_dir(void);
int ssh_file_readaccess_ok(const char *file);

/* macro for byte ordering */
u64 ntohll(u64);
#define htonll(x) ntohll(x)

/* channels1.c */
int channel_open_session1(CHANNEL *channel);
int channel_request_pty_size1(CHANNEL *channel, const char *terminal,
    int cols, int rows);
int channel_change_pty_size1(CHANNEL *channel, int cols, int rows);
int channel_request_shell1(CHANNEL *channel);
int channel_request_exec1(CHANNEL *channel, const char *cmd);
int channel_handle1(SSH_SESSION *session, int type);
int channel_write1(CHANNEL *channel, const void *data, int len);

/* session.c */

int ssh_handle_packets(SSH_SESSION *session);

/* match.c */
int match_hostname(const char *host, const char *pattern, unsigned int len);

/* log.c */

#define _enter_function(sess) \
	do {\
		if((sess)->log_verbosity >= SSH_LOG_FUNCTIONS){ \
			ssh_log((sess),SSH_LOG_FUNCTIONS,"entering function %s line %d in " __FILE__ , __FUNCTION__,__LINE__);\
			(sess)->log_indent++; \
		} \
	} while(0)

#define _leave_function(sess) \
	do { \
		if((sess)->log_verbosity >= SSH_LOG_FUNCTIONS){ \
			(sess)->log_indent--; \
			ssh_log((sess),SSH_LOG_FUNCTIONS,"leaving function %s line %d in " __FILE__ , __FUNCTION__,__LINE__);\
		}\
	} while(0)

#define enter_function() _enter_function(session)
#define leave_function() _leave_function(session)

/** Free memory space */
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/** Overwrite the complete string with 'X' */
#define BURN_STRING(x) do { if ((x) != NULL) memset((x), 'X', strlen((x))); } while(0)

#ifdef HAVE_LIBGCRYPT
/* gcrypt_missing.c */
int my_gcry_dec2bn(bignum *bn, const char *data);
char *my_gcry_bn2dec(bignum bn);
#endif /* !HAVE_LIBGCRYPT */

#ifdef __cplusplus
}
#endif

#endif /* _LIBSSH_PRIV_H */
/* vim: set ts=2 sw=2 et cindent: */
