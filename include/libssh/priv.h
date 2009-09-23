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

/*
 * priv.h file
 * This include file contains everything you shouldn't deal with in
 * user programs. Consider that anything in this file might change
 * without notice; libssh.h file will keep backward compatibility
 * on binary & source
 */

#ifndef _LIBSSH_PRIV_H
#define _LIBSSH_PRIV_H

#ifdef _MSC_VER
#define snprintf _snprintf
/** Imitate define of inttypes.h */
#define PRIdS "Id"
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define strtoull _strtoui64
#define isblank(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')
#else
#include <unistd.h>
#define PRIdS "zd"
#endif

#include "config.h"
#include "libssh/libssh.h"
#include "libssh/callback.h"
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
typedef struct pollfd ssh_pollfd_t;
#else /* HAVE_POLL */
typedef struct ssh_pollfd_struct {
  socket_t fd;      /* file descriptor */
  short events;     /* requested events */
  short revents;    /* returned events */
} ssh_pollfd_t;

/* poll.c */
#ifndef POLLIN
# define POLLIN    0x001  /* There is data to read.  */
#endif
#ifndef POLLPRI
#define POLLPRI   0x002  /* There is urgent data to read.  */
#endif
#ifndef POLLOUT
#define POLLOUT   0x004  /* Writing now will not block.  */
#endif

#ifndef POLLERR
#define POLLERR   0x008  /* Error condition.  */
#endif
#ifndef POLLHUP
#define POLLHUP   0x010  /* Hung up.  */
#endif
#ifndef POLLNVAL
#define POLLNVAL  0x020  /* Invalid polling request.  */
#endif

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
#ifdef _MSC_VER
#pragma pack(1)
#endif
struct ssh_string_struct {
	uint32_t size;
	unsigned char string[MAX_PACKET_LEN];
}
#if !defined(__SUNPRO_C) && !defined(_MSC_VER)
__attribute__ ((packed))
#endif
#ifdef _MSC_VER
#pragma pack()
#endif
;

/** Describes a buffer state at a moment
 */
struct ssh_buffer_struct {
    char *data;
    uint32_t used;
    uint32_t allocated;
    uint32_t pos;
};

/* i should remove it one day */
typedef struct packet_struct {
	int valid;
	uint32_t len;
	uint8_t type;
} PACKET;

typedef struct kex_struct {
	unsigned char cookie[16];
	char **methods;
} KEX;

struct ssh_public_key_struct {
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

struct ssh_private_key_struct {
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
    ssh_string rsa_sign;
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
    ssh_callbacks callbacks; /* Callbacks to user functions */
    long timeout; /* seconds */
    long timeout_usec;
    int ssh2allowed;
    int ssh1allowed;
    char *dsakey;
    char *rsakey; /* host key for server implementation */
    int log_verbosity;

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
    ssh_string server_pubkey;
    const char *server_pubkey_type;
    int do_compress_out; /* idem */
    int do_compress_in; /* don't set them, set the option instead */
    void *compress_out_ctx; /* don't touch it */
    void *compress_in_ctx; /* really, don't */
} CRYPTO;

struct ssh_channel_struct {
    struct ssh_channel_struct *prev;
    struct ssh_channel_struct *next;
    SSH_SESSION *session; /* SSH_SESSION pointer */
    uint32_t local_channel;
    uint32_t local_window;
    int local_eof;
    uint32_t local_maxpacket;

    uint32_t remote_channel;
    uint32_t remote_window;
    int remote_eof; /* end of file received */
    uint32_t remote_maxpacket;
    int open; /* shows if the channel is still opened */
    int delayed_close;
    ssh_buffer stdout_buffer;
    ssh_buffer stderr_buffer;
    void *userarg;
    int version;
    int blocking;
    int exit_status;
};

struct ssh_agent_struct {
  struct socket *sock;
  ssh_buffer ident;
  unsigned int count;
};

struct ssh_keys_struct {
  const char *privatekey;
  const char *publickey;
};

enum ssh_scp_states {
  SSH_SCP_NEW,          //Data structure just created
  SSH_SCP_WRITE_INITED, //Gave our intention to write
  SSH_SCP_WRITE_WRITING,//File was opened and currently writing
  SSH_SCP_READ_INITED,  //Gave our intention to read
  SSH_SCP_READ_REQUESTED, //We got a read request
  SSH_SCP_READ_READING, //File is opened and reading
  SSH_SCP_ERROR,         //Something bad happened
  SSH_SCP_TERMINATED	//Transfer finished
};

struct ssh_scp_struct {
  ssh_session session;
  int mode;
  int recursive;
  ssh_channel channel;
  char *location;
  enum ssh_scp_states state;
  size_t filelen;
  size_t processed;
  enum ssh_scp_request_types request_type;
  char *request_name;
  char *warning;
  int request_mode;
};

struct ssh_message_struct;

struct ssh_session_struct {
    struct error_struct error;
    struct socket *socket;
    SSH_OPTIONS *options;
    char *serverbanner;
    char *clientbanner;
    int protoversion;
    int server;
    int client;
    int openssh;
    uint32_t send_seq;
    uint32_t recv_seq;
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

    ssh_string banner; /* that's the issue banner from
                       the server */
    char *remotebanner; /* that's the SSH- banner from
                           remote host. */
    char *discon_msg; /* disconnect message from
                         the remote host */
    ssh_buffer in_buffer;
    PACKET in_packet;
    ssh_buffer out_buffer;

    /* the states are used by the nonblocking stuff to remember */
    /* where it was before being interrupted */
    int packet_state;
    int dh_handshake_state;
    ssh_string dh_server_signature; //information used by dh_handshake.

    KEX server_kex;
    KEX client_kex;
    ssh_buffer in_hashbuf;
    ssh_buffer out_hashbuf;
    CRYPTO *current_crypto;
    CRYPTO *next_crypto;  /* next_crypto is going to be used after a SSH2_MSG_NEWKEYS */

    ssh_channel channels; /* linked list of channels */
    int maxchannel;
    int exec_channel_opened; /* version 1 only. more
                                info in channels1.c */
    ssh_agent agent; /* ssh agent */

/* keyb interactive data */
    struct ssh_kbdint_struct *kbdint;
    int version; /* 1 or 2 */
    /* server host keys */
    ssh_private_key rsa_key;
    ssh_private_key dsa_key;
    /* auths accepted by server */
    int auth_methods;
    int hostkeys; /* contains type of host key wanted by client, in server impl */
    struct ssh_list *ssh_message_list; /* list of delayed SSH messages */
    int (*ssh_message_callback)( struct ssh_session_struct *session, ssh_message msg);
    int log_verbosity; /*cached copy of the option structure */
    int log_indent; /* indentation level in enter_function logs */
};

struct ssh_kbdint_struct {
    uint32_t nprompts;
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
    struct ssh_public_key_struct *public_key;
    char signature_state;
};

struct ssh_channel_request_open {
    int type;
    uint32_t sender;
    uint32_t window;
    uint32_t packet_size;
    char *originator;
    uint16_t originator_port;
    char *destination;
    uint16_t destination_port;
};

struct ssh_service_request {
    char *service;
};

struct ssh_channel_request {
    int type;
    ssh_channel channel;
    uint8_t want_reply;
    /* pty-req type specifics */
    char *TERM;
    uint32_t width;
    uint32_t height;
    uint32_t pxwidth;
    uint32_t pxheight;
    ssh_string modes;

    /* env type request */
    char *var_name;
    char *var_value;
    /* exec type request */
    char *command;
    /* subsystem */
    char *subsystem;
};

struct ssh_message_struct {
    SSH_SESSION *session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
    struct ssh_service_request service_request;
};

#ifndef _WIN32
/* agent.c */
/**
 * @brief Create a new ssh agent structure.
 *
 * @return An allocated ssh agent structure or NULL on error.
 */
struct ssh_agent_struct *agent_new(struct ssh_session_struct *session);

void agent_close(struct ssh_agent_struct *agent);

/**
 * @brief Free an allocated ssh agent structure.
 *
 * @param agent The ssh agent structure to free.
 */
void agent_free(struct ssh_agent_struct *agent);

/**
 * @brief Check if the ssh agent is running.
 *
 * @param session The ssh session to check for the agent.
 *
 * @return 1 if it is running, 0 if not.
 */
int agent_is_running(struct ssh_session_struct *session);

int agent_get_ident_count(struct ssh_session_struct *session);

struct ssh_public_key_struct *agent_get_next_ident(struct ssh_session_struct *session,
    char **comment);

struct ssh_public_key_struct *agent_get_first_ident(struct ssh_session_struct *session,
    char **comment);

ssh_string agent_sign_data(struct ssh_session_struct *session,
    struct ssh_buffer_struct *data,
    struct ssh_public_key_struct *pubkey);
#endif

/* poll.c */
int ssh_poll(ssh_pollfd_t *fds, nfds_t nfds, int timeout);
typedef struct ssh_poll_ctx SSH_POLL_CTX;
typedef struct ssh_poll SSH_POLL;

/**
 * @brief SSH poll callback.
 *
 * @param p             Poll object this callback belongs to.
 * @param fd            The raw socket.
 * @param revents       The current poll events on the socket.
 * @param userdata      Userdata to be passed to the callback function.
 *
 * @return              0 on success, < 0 if you removed the poll object from
 *                      it's poll context.
 */
typedef int (*ssh_poll_callback)(SSH_POLL *p, int fd, int revents,
    void *userdata);


SSH_POLL *ssh_poll_new(socket_t fd, short events, ssh_poll_callback cb,
    void *userdata);
void ssh_poll_free(SSH_POLL *p);
SSH_POLL_CTX *ssh_poll_get_ctx(SSH_POLL *p);
short ssh_poll_get_events(SSH_POLL *p);
void ssh_poll_set_events(SSH_POLL *p, short events);
void ssh_poll_add_events(SSH_POLL *p, short events);
void ssh_poll_remove_events(SSH_POLL *p, short events);
socket_t ssh_poll_get_fd(SSH_POLL *p);
void ssh_poll_set_callback(SSH_POLL *p, ssh_poll_callback cb, void *userdata);
SSH_POLL_CTX *ssh_poll_ctx_new(size_t chunk_size);
void ssh_poll_ctx_free(SSH_POLL_CTX *ctx);
int ssh_poll_ctx_add(SSH_POLL_CTX *ctx, SSH_POLL *p);
void ssh_poll_ctx_remove(SSH_POLL_CTX *ctx, SSH_POLL *p);
int ssh_poll_ctx(SSH_POLL_CTX *ctx, int timeout);

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
int ssh_socket_completeread(struct socket *s, void *buffer, uint32_t len);
int ssh_socket_completewrite(struct socket *s, const void *buffer, uint32_t len);
int ssh_socket_wait_for_data(struct socket *s, SSH_SESSION *session, uint32_t len);
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

/* config.c */
int ssh_config_parse_file(ssh_options opt, const char *filename);

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

ssh_string dh_get_e(SSH_SESSION *session);
ssh_string dh_get_f(SSH_SESSION *session);
int dh_import_f(SSH_SESSION *session,ssh_string f_string);
int dh_import_e(SSH_SESSION *session, ssh_string e_string);
void dh_import_pubkey(SSH_SESSION *session,ssh_string pubkey_string);
int dh_build_k(SSH_SESSION *session);
int make_sessionid(SSH_SESSION *session);
/* add data for the final cookie */
int hashbufin_add_cookie(SSH_SESSION *session, unsigned char *cookie);
int hashbufout_add_cookie(SSH_SESSION *session);
int generate_session_keys(SSH_SESSION *session);
int sig_verify(SSH_SESSION *session, ssh_public_key pubkey,
    SIGNATURE *signature, unsigned char *digest, int size);
/* returns 1 if server signature ok, 0 otherwise. The NEXT crypto is checked, not the current one */
int signature_verify(SSH_SESSION *session,ssh_string signature);
bignum make_string_bn(ssh_string string);
ssh_string make_bignum_string(bignum num);

/* in crypt.c */
uint32_t packet_decrypt_len(SSH_SESSION *session,char *crypted);
int packet_decrypt(SSH_SESSION *session, void *packet,unsigned int len);
unsigned char *packet_encrypt(SSH_SESSION *session,void *packet,unsigned int len);
 /* it returns the hmac buffer if exists*/
int packet_hmac_verify(SSH_SESSION *session,ssh_buffer buffer,unsigned char *mac);

/* in packet.c */

void packet_parse(SSH_SESSION *session);
int packet_send(SSH_SESSION *session);

int packet_read(SSH_SESSION *session);
int packet_translate(SSH_SESSION *session);
int packet_wait(SSH_SESSION *session,int type,int blocking);
int packet_flush(SSH_SESSION *session, int enforce_blocking);

/* connect.c */
int ssh_regex_init(void);
void ssh_regex_finalize(void);
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

ssh_private_key _privatekey_from_file(void *session, const char *filename,
    int type);
ssh_string try_publickey_from_file(SSH_SESSION *session,
    struct ssh_keys_struct keytab,
    char **privkeyfile, int *type);

/* in keys.c */
const char *ssh_type_to_char(int type);
int ssh_type_from_name(const char *name);
ssh_buffer ssh_userauth_build_digest(SSH_SESSION *session, ssh_message msg, char *service);

ssh_private_key privatekey_make_dss(SSH_SESSION *session, ssh_buffer buffer);
ssh_private_key privatekey_make_rsa(SSH_SESSION *session, ssh_buffer buffer,
    const char *type);
ssh_private_key privatekey_from_string(SSH_SESSION *session, ssh_string privkey_s);

ssh_public_key publickey_make_dss(SSH_SESSION *session, ssh_buffer buffer);
ssh_public_key publickey_make_rsa(SSH_SESSION *session, ssh_buffer buffer, int type);
ssh_public_key publickey_from_string(SSH_SESSION *session, ssh_string pubkey_s);
SIGNATURE *signature_from_string(SSH_SESSION *session, ssh_string signature,ssh_public_key pubkey,int needed_type);
void signature_free(SIGNATURE *sign);
ssh_string ssh_do_sign_with_agent(struct ssh_session_struct *session,
    struct ssh_buffer_struct *buf, struct ssh_public_key_struct *publickey);
ssh_string ssh_do_sign(SSH_SESSION *session,ssh_buffer sigbuf,
        ssh_private_key privatekey);
ssh_string ssh_sign_session_id(SSH_SESSION *session, ssh_private_key privatekey);
ssh_string ssh_encrypt_rsa1(SSH_SESSION *session, ssh_string data, ssh_public_key key);
/* channel.c */
void channel_handle(SSH_SESSION *session, int type);
ssh_channel channel_new(SSH_SESSION *session);
int channel_default_bufferize(ssh_channel channel, void *data, int len,
        int is_stderr);
uint32_t ssh_channel_new_id(SSH_SESSION *session);
ssh_channel ssh_channel_from_local(SSH_SESSION *session, uint32_t id);
int channel_write_common(ssh_channel channel, const void *data,
    uint32_t len, int is_stderr);

/* options.c */

/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(SSH_OPTIONS *opt);
int ssh_options_default_ssh_dir(SSH_OPTIONS *opt);
int ssh_options_default_known_hosts_file(SSH_OPTIONS *opt);

/* buffer.c */
int buffer_add_ssh_string(ssh_buffer buffer, ssh_string string);
int buffer_add_u8(ssh_buffer buffer, uint8_t data);
int buffer_add_u32(ssh_buffer buffer, uint32_t data);
int buffer_add_u64(ssh_buffer buffer, uint64_t data);
int buffer_add_data(ssh_buffer buffer, const void *data, uint32_t len);
int buffer_prepend_data(ssh_buffer buffer, const void *data, uint32_t len);
int buffer_add_buffer(ssh_buffer buffer, ssh_buffer source);
int buffer_reinit(ssh_buffer buffer);

/* buffer_get_rest returns a pointer to the current position into the buffer */
void *buffer_get_rest(ssh_buffer buffer);
/* buffer_get_rest_len returns the number of bytes which can be read */
uint32_t buffer_get_rest_len(ssh_buffer buffer);

/* buffer_read_*() returns the number of bytes read, except for ssh strings */
int buffer_get_u8(ssh_buffer buffer, uint8_t *data);
int buffer_get_u32(ssh_buffer buffer, uint32_t *data);
int buffer_get_u64(ssh_buffer buffer, uint64_t *data);

uint32_t buffer_get_data(ssh_buffer buffer, void *data, uint32_t requestedlen);
/* buffer_get_ssh_string() is an exception. if the String read is too large or invalid, it will answer NULL. */
ssh_string buffer_get_ssh_string(ssh_buffer buffer);
/* gets a string out of a SSH-1 mpint */
ssh_string buffer_get_mpint(ssh_buffer buffer);
/* buffer_pass_bytes acts as if len bytes have been read (used for padding) */
uint32_t buffer_pass_bytes_end(ssh_buffer buffer, uint32_t len);
uint32_t buffer_pass_bytes(ssh_buffer buffer, uint32_t len);

/* in base64.c */
ssh_buffer base64_to_bin(const char *source);
unsigned char *bin_to_base64(const unsigned char *source, int len);

/* gzip.c */
int compress_buffer(SSH_SESSION *session,ssh_buffer buf);
int decompress_buffer(SSH_SESSION *session,ssh_buffer buf, size_t maxlen);

/* wrapper.c */
int crypt_set_algorithms(SSH_SESSION *);
int crypt_set_algorithms_server(SSH_SESSION *session);
CRYPTO *crypto_new(void);
void crypto_free(CRYPTO *crypto);

/* crc32.c */
uint32_t ssh_crc32(const char *buf, uint32_t len);

/* auth1.c */
int ssh_userauth1_none(SSH_SESSION *session, const char *username);
int ssh_userauth1_offer_pubkey(SSH_SESSION *session, const char *username,
        int type, ssh_string pubkey);
int ssh_userauth1_password(SSH_SESSION *session, const char *username,
        const char *password);
/* in misc.c */
/* gets the user home dir. */
char *ssh_get_user_home_dir(void);
int ssh_file_readaccess_ok(const char *file);

/* macro for byte ordering */
uint64_t ntohll(uint64_t);
#define htonll(x) ntohll(x)

/* list processing */

struct ssh_list {
  struct ssh_iterator *root;
  struct ssh_iterator *end;
};

struct ssh_iterator {
  struct ssh_iterator *next;
  const void *data;
};

struct ssh_list *ssh_list_new(void);
void ssh_list_free(struct ssh_list *list);
struct ssh_iterator *ssh_list_get_iterator(const struct ssh_list *list);
int ssh_list_add(struct ssh_list *list, const void *data);
void ssh_list_remove(struct ssh_list *list, struct ssh_iterator *iterator);

/** @brief fetch the head element of a list and remove it from list
 * @param list the ssh_list to use
 * @return the first element of the list
 */
const void *_ssh_list_get_head(struct ssh_list *list);

#define ssh_iterator_value(type, iterator)\
  ((type)((iterator)->data))
/** @brief fetch the head element of a list and remove it from list
 * @param type type of the element to return
 * @param list the ssh_list to use
 * @return the first element of the list
 */
#define ssh_list_get_head(type, ssh_list)\
  ((type)_ssh_list_get_head(ssh_list))


/* channels1.c */
int channel_open_session1(ssh_channel channel);
int channel_request_pty_size1(ssh_channel channel, const char *terminal,
    int cols, int rows);
int channel_change_pty_size1(ssh_channel channel, int cols, int rows);
int channel_request_shell1(ssh_channel channel);
int channel_request_exec1(ssh_channel channel, const char *cmd);
int channel_handle1(SSH_SESSION *session, int type);
int channel_write1(ssh_channel channel, const void *data, int len);

/* session.c */

int ssh_handle_packets(SSH_SESSION *session);

/* match.c */
int match_hostname(const char *host, const char *pattern, unsigned int len);

/* messages.c */

void message_handle(SSH_SESSION *session, uint32_t type);
int ssh_execute_message_callbacks(SSH_SESSION *session);

/* scp.c */
int ssh_scp_read_string(ssh_scp scp, char *buffer, size_t len);
int ssh_scp_integer_mode(const char *mode);
char *ssh_scp_string_mode(int mode);
int ssh_scp_response(ssh_scp scp, char **response);

/* log.c */

#ifndef __FUNCTION__
#if defined(__SUNPRO_C)
#define __FUNCTION__ __func__
#endif
#endif

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

#ifdef DEBUG_CALLTRACE
#define enter_function() _enter_function(session)
#define leave_function() _leave_function(session)
#else
#define enter_function() (void)session
#define leave_function() (void)session
#endif

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
