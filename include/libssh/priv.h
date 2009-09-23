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
enum public_key_types_e{
	TYPE_DSS=1,
	TYPE_RSA,
	TYPE_RSA1
};

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

struct ssh_crypto_struct {
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
};

struct ssh_keys_struct {
  const char *privatekey;
  const char *publickey;
};

struct ssh_message_struct;

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
    ssh_options options;
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
    ssh_session session;
    int type;
    struct ssh_auth_request auth_request;
    struct ssh_channel_request_open channel_request_open;
    struct ssh_channel_request channel_request;
    struct ssh_service_request service_request;
};



/* session.c */

void ssh_cleanup(ssh_session session);

/* client.c */

int ssh_send_banner(ssh_session session, int is_server);
char *ssh_get_banner(ssh_session session);

/* config.c */
int ssh_config_parse_file(ssh_options opt, const char *filename);

/* errors.c */
void ssh_set_error(void *error, int code, const char *descr, ...) PRINTF_ATTRIBUTE(3, 4);

/* in dh.c */
/* DH key generation */
void ssh_print_bignum(const char *which,bignum num);
int dh_generate_e(ssh_session session);
int dh_generate_f(ssh_session session);
int dh_generate_x(ssh_session session);
int dh_generate_y(ssh_session session);

int ssh_crypto_init(void);
void ssh_crypto_finalize(void);

ssh_string dh_get_e(ssh_session session);
ssh_string dh_get_f(ssh_session session);
int dh_import_f(ssh_session session,ssh_string f_string);
int dh_import_e(ssh_session session, ssh_string e_string);
void dh_import_pubkey(ssh_session session,ssh_string pubkey_string);
int dh_build_k(ssh_session session);
int make_sessionid(ssh_session session);
/* add data for the final cookie */
int hashbufin_add_cookie(ssh_session session, unsigned char *cookie);
int hashbufout_add_cookie(ssh_session session);
int generate_session_keys(ssh_session session);
int sig_verify(ssh_session session, ssh_public_key pubkey,
    SIGNATURE *signature, unsigned char *digest, int size);
/* returns 1 if server signature ok, 0 otherwise. The NEXT crypto is checked, not the current one */
int signature_verify(ssh_session session,ssh_string signature);
bignum make_string_bn(ssh_string string);
ssh_string make_bignum_string(bignum num);

/* in crypt.c */
uint32_t packet_decrypt_len(ssh_session session,char *crypted);
int packet_decrypt(ssh_session session, void *packet,unsigned int len);
unsigned char *packet_encrypt(ssh_session session,void *packet,unsigned int len);
 /* it returns the hmac buffer if exists*/
int packet_hmac_verify(ssh_session session,ssh_buffer buffer,unsigned char *mac);


/* connect.c */
int ssh_regex_init(void);
void ssh_regex_finalize(void);
ssh_session ssh_session_new();
socket_t ssh_connect_host(ssh_session session, const char *host,const char
        *bind_addr, int port, long timeout, long usec);

/* in kex.c */
extern const char *ssh_kex_nums[];
int ssh_send_kex(ssh_session session, int server_kex);
void ssh_list_kex(ssh_session session, KEX *kex);
int set_kex(ssh_session session);
int ssh_get_kex(ssh_session session, int server_kex);
int verify_existing_algo(int algo, const char *name);
char **space_tokenize(const char *chain);
int ssh_get_kex1(ssh_session session);
char *ssh_find_matching(const char *in_d, const char *what_d);

/* in keys.c */
const char *ssh_type_to_char(int type);
int ssh_type_from_name(const char *name);
ssh_buffer ssh_userauth_build_digest(ssh_session session, ssh_message msg, char *service);

ssh_private_key privatekey_make_dss(ssh_session session, ssh_buffer buffer);
ssh_private_key privatekey_make_rsa(ssh_session session, ssh_buffer buffer,
    const char *type);
ssh_private_key privatekey_from_string(ssh_session session, ssh_string privkey_s);

ssh_public_key publickey_make_dss(ssh_session session, ssh_buffer buffer);
ssh_public_key publickey_make_rsa(ssh_session session, ssh_buffer buffer, int type);
ssh_public_key publickey_from_string(ssh_session session, ssh_string pubkey_s);
SIGNATURE *signature_from_string(ssh_session session, ssh_string signature,ssh_public_key pubkey,int needed_type);
void signature_free(SIGNATURE *sign);
ssh_string ssh_do_sign_with_agent(struct ssh_session_struct *session,
    struct ssh_buffer_struct *buf, struct ssh_public_key_struct *publickey);
ssh_string ssh_do_sign(ssh_session session,ssh_buffer sigbuf,
        ssh_private_key privatekey);
ssh_string ssh_sign_session_id(ssh_session session, ssh_private_key privatekey);
ssh_string ssh_encrypt_rsa1(ssh_session session, ssh_string data, ssh_public_key key);


/* options.c */

/* this function must be called when no specific username has been asked. it has to guess it */
int ssh_options_default_username(ssh_options opt);
int ssh_options_default_ssh_dir(ssh_options opt);
int ssh_options_default_known_hosts_file(ssh_options opt);

/* in base64.c */
ssh_buffer base64_to_bin(const char *source);
unsigned char *bin_to_base64(const unsigned char *source, int len);

/* gzip.c */
int compress_buffer(ssh_session session,ssh_buffer buf);
int decompress_buffer(ssh_session session,ssh_buffer buf, size_t maxlen);

/* wrapper.c */
int crypt_set_algorithms(ssh_session );
int crypt_set_algorithms_server(ssh_session session);
struct ssh_crypto_struct *crypto_new(void);
void crypto_free(struct ssh_crypto_struct *crypto);

/* crc32.c */
uint32_t ssh_crc32(const char *buf, uint32_t len);

/* auth1.c */
int ssh_userauth1_none(ssh_session session, const char *username);
int ssh_userauth1_offer_pubkey(ssh_session session, const char *username,
        int type, ssh_string pubkey);
int ssh_userauth1_password(ssh_session session, const char *username,
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
int channel_handle1(ssh_session session, int type);
int channel_write1(ssh_channel channel, const void *data, int len);

/* match.c */
int match_hostname(const char *host, const char *pattern, unsigned int len);

/* messages.c */

void message_handle(ssh_session session, uint32_t type);
int ssh_execute_message_callbacks(ssh_session session);

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
