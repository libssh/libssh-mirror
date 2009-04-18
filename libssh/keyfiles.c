/*
 * keyfiles.c - private and public key handling for authentication.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include "libssh/priv.h"

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#elif defined HAVE_LIBCRYPTO
#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#endif /* HAVE_LIBCRYPTO */

#define MAXLINESIZE 80

#ifdef HAVE_LIBGCRYPT

#define MAX_KEY_SIZE 32
#define MAX_PASSPHRASE_SIZE 1024
#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"
#define ASN1_INTEGER 2
#define ASN1_SEQUENCE 48
#define PKCS5_SALT_LEN 8

static int load_iv(char *header, unsigned char *iv, int iv_len) {
  int i;
  int j;
  int k;

  memset(iv, 0, iv_len);
  for (i = 0; i < iv_len; i++) {
    if ((header[2*i] >= '0') && (header[2*i] <= '9'))
      j = header[2*i] - '0';
    else if ((header[2*i] >= 'A') && (header[2*i] <= 'F'))
      j = header[2*i] - 'A' + 10;
    else if ((header[2*i] >= 'a') && (header[2*i] <= 'f'))
      j = header[2*i] - 'a' + 10;
    else
      return 0;
    if ((header[2*i+1] >= '0') && (header[2*i+1] <= '9'))
      k = header[2*i+1] - '0';
    else if ((header[2*i+1] >= 'A') && (header[2*i+1] <= 'F'))
      k = header[2*i+1] - 'A' + 10;
    else if ((header[2*i+1] >= 'a') && (header[2*i+1] <= 'f'))
      k = header[2*i+1] - 'a' + 10;
    else
      return 0;
    iv[i] = (j << 4) + k;
  }
  return 1;
}

static u32 char_to_u32(unsigned char *data, u32 size) {
  u32 ret;
  u32 i;

  for (i = 0, ret = 0; i < size; ret = ret << 8, ret += data[i++])
    ;
  return ret;
}

static u32 asn1_get_len(BUFFER *buffer) {
  u32 len;
  unsigned char tmp[4];

  if (buffer_get_data(buffer,tmp,1) == 0) {
    return 0;
  }

  if (tmp[0] > 127) {
    len = tmp[0] & 127;
    if (len > 4) {
      return 0; /* Length doesn't fit in u32. Can this really happen? */
    }
    if (buffer_get_data(buffer,tmp,len) == 0) {
      return 0;
    }
    len = char_to_u32(tmp, len);
  } else {
    len = char_to_u32(tmp, 1);
  }

  return len;
}

static STRING *asn1_get_int(BUFFER *buffer) {
  STRING *str;
  unsigned char type;
  u32 size;

  if (buffer_get_data(buffer, &type, 1) == 0 || type != ASN1_INTEGER) {
    return NULL;
  }
  size = asn1_get_len(buffer);
  if (size == 0) {
    return NULL;
  }

  str = string_new(size);
  if (str == NULL) {
    return NULL;
  }

  if (buffer_get_data(buffer, str->string, size) == 0) {
    string_free(str);
    return NULL;
  }

  return str;
}

static int asn1_check_sequence(BUFFER *buffer) {
  unsigned char tmp;
  unsigned char *j;
  int i;
  u32 size;
  u32 padding;

  if (!buffer_get_data(buffer,&tmp,1) || tmp != ASN1_SEQUENCE)
    return 0;
  size=asn1_get_len(buffer);
  if ((padding = buffer_get_len(buffer) - buffer->pos - size) > 0)
    for (i = buffer_get_len(buffer) - buffer->pos - size,
         j = buffer_get(buffer) + size + buffer->pos; i; i--, j++)
    {
      if (*j != padding)                     /* padding is allowed */
        return 0;                            /* but nothing else */
    }
  return 1;
}

static int read_line(char *data, unsigned int len, FILE *fp) {
  char tmp;
  unsigned int i;

  for (i=0; fread(&tmp, 1, 1, fp) && tmp!='\n' && i<len; data[i++]=tmp)
    ;
  if (tmp=='\n')
    return i;
  if (i>=len)
    return -1;
  return 0;
}

static int passphrase_to_key(char *data, unsigned int datalen,
    unsigned char *salt, unsigned char *key, unsigned int keylen) {
  MD5CTX md;
  unsigned char digest[MD5_DIGEST_LEN];
  unsigned int i;
  unsigned int j;
  unsigned int md_not_empty;

  for (j=0,md_not_empty=0;j<keylen;)
  {
    md = md5_init();
    if (!md)
      return 0;
    if (md_not_empty)
      md5_update(md,digest,MD5_DIGEST_LEN);
    else
      md_not_empty=1;
    md5_update(md,data,datalen);
    if (salt)
      md5_update(md, salt, PKCS5_SALT_LEN);
    md5_final(digest,md);
    for (i = 0; j < keylen && i < MD5_DIGEST_LEN; j++, i++)
      if (key)
        key[j] = digest[i];
  }
  return 1;
}

static int privatekey_decrypt(int algo, int mode, unsigned int key_len,
                       unsigned char *iv, unsigned int iv_len,
                       BUFFER *data, ssh_auth_callback cb,
                       void *userdata,
                       char *desc)
{
  gcry_cipher_hd_t cipher;
  int rc = -1;
  char passphrase[MAX_PASSPHRASE_SIZE] = {0};
  unsigned char key[MAX_KEY_SIZE] = {0};
  unsigned char *tmp;
  gcry_error_t err;

  if (!algo)
    return 1;

  if (cb) {
    rc = (*cb)(desc, passphrase, MAX_PASSPHRASE_SIZE, 0, 0, userdata);
    if (rc < 0) {
      return 0;
    }
  } else if (cb == NULL && userdata != NULL) {
    snprintf(passphrase, MAX_PASSPHRASE_SIZE, "%s", (char *) userdata);
  }
  passphrase_to_key(passphrase, strlen(passphrase), iv, key, key_len);
  if (gcry_cipher_open(&cipher, algo, mode, 0)
      || gcry_cipher_setkey(cipher, key, key_len)
      || gcry_cipher_setiv(cipher, iv, iv_len)
      || !(tmp = malloc(buffer_get_len(data) * sizeof (char)))
      || (err = gcry_cipher_decrypt(cipher, tmp, buffer_get_len(data),
                                    buffer_get(data), buffer_get_len(data))))
  {
    gcry_cipher_close(cipher);
    return 0;
  }
  memcpy(buffer_get(data), tmp, buffer_get_len(data));
  SAFE_FREE(tmp);
  gcry_cipher_close(cipher);
  return 1;
}

static int privatekey_dek_header(char *header, unsigned int header_len,
    int *algo, int *mode, unsigned int *key_len, unsigned char **iv,
    unsigned int *iv_len) {
  unsigned int iv_pos;

  if (header_len > 13 && !strncmp("DES-EDE3-CBC", header, 12))
  {
    *algo = GCRY_CIPHER_3DES;
    iv_pos = 13;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 24;
    *iv_len = 8;
  }
  else if (header_len > 8 && !strncmp("DES-CBC", header, 7))
  {
    *algo = GCRY_CIPHER_DES;
    iv_pos = 8;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 8;
    *iv_len = 8;
  }
  else if (header_len > 12 && !strncmp("AES-128-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES128;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 16;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-192-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES192;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 24;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-256-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES256;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 32;
    *iv_len = 16;
  }
  else
    return 0;
  *iv = malloc(*iv_len);
  if (*iv == NULL) {
    return 0;
  }
  load_iv(header + iv_pos, *iv, *iv_len);
  return 1;
}

static BUFFER *privatekey_file_to_buffer(FILE *fp, int type,
    ssh_auth_callback cb, void *userdata, char *desc) {
  char buf[MAXLINESIZE] = {0};
  char *header_begin;
  unsigned int header_begin_size;
  char *header_end;
  unsigned int header_end_size;
  BUFFER *buffer=buffer_new();
  BUFFER *ret;
  int len;
  int algo = 0;
  int mode = 0;
  unsigned int key_len = 0;
  unsigned char *iv = NULL;
  unsigned int iv_len = 0;

  switch(type)
  {
    case TYPE_DSS:
      header_begin=DSA_HEADER_BEGIN;
      header_end=DSA_HEADER_END;
      break;
    case TYPE_RSA:
      header_begin=RSA_HEADER_BEGIN;
      header_end=RSA_HEADER_END;
      break;
    default:
      return NULL;
  }
  header_begin_size=strlen(header_begin);
  header_end_size=strlen(header_end);
  while (read_line(buf,MAXLINESIZE,fp) && strncmp(buf,header_begin,header_begin_size))
    ;
  len = read_line(buf, MAXLINESIZE, fp);
  if (len > 11 && !strncmp("Proc-Type: 4,ENCRYPTED", buf, 11))
  {
    len = read_line(buf, MAXLINESIZE, fp);
    if (len > 10 && !strncmp("DEK-Info: ", buf, 10))
    {
      if (!privatekey_dek_header(buf + 10, len - 10, &algo, &mode, &key_len,
                                 &iv, &iv_len)
          || read_line(buf, MAXLINESIZE, fp))
      {
        buffer_free(buffer);
        free(iv);
        return NULL;
      }
    }
    else
    {
      buffer_free(buffer);
      free(iv);
      return NULL;
    }
  }
  else
    buffer_add_data(buffer,buf,len);
  while ((len = read_line(buf,MAXLINESIZE,fp))
         && strncmp(buf,header_end,header_end_size))
  {
    if (len == -1)
    {
      buffer_free(buffer);
      free(iv);
      return NULL;
    }
    buffer_add_data(buffer,buf,len);
  }
  if (strncmp(buf,header_end,header_end_size))
  {
    buffer_free(buffer);
    free(iv);
    return NULL;
  }
  buffer_add_data(buffer,"\0",1);
  ret=base64_to_bin(buffer_get(buffer));
  buffer_free(buffer);
  if (algo)
  {
    if (!privatekey_decrypt(algo, mode, key_len, iv, iv_len, ret, cb, userdata, desc))
    {
      free(iv);
      return NULL;
    }
  }
  free(iv);
  return ret;
}

static int read_rsa_privatekey(FILE *fp, gcry_sexp_t *r,
    ssh_auth_callback cb, void *userdata, char *desc) {
  STRING *n;
  STRING *e;
  STRING *d;
  STRING *p;
  STRING *q;
  STRING *unused1;
  STRING *unused2;
  STRING *u;
  STRING *v;
  BUFFER *buffer;

  if (!(buffer=privatekey_file_to_buffer(fp, TYPE_RSA, cb, userdata, desc)))
    return 0;
  if (!asn1_check_sequence(buffer))
  {
    buffer_free(buffer);
    return 0;
  }
  v=asn1_get_int(buffer);
  if (ntohl(v->size)!=1 || v->string[0]!=0)
  {
    buffer_free(buffer);
    return 0;
  }
  n=asn1_get_int(buffer);
  e=asn1_get_int(buffer);
  d=asn1_get_int(buffer);
  q=asn1_get_int(buffer);
  p=asn1_get_int(buffer);
  unused1=asn1_get_int(buffer);
  unused2=asn1_get_int(buffer);
  u=asn1_get_int(buffer);
  buffer_free(buffer);
  if (!n || !e || !d || !p || !q || !unused1 || !unused2 || !u)
    return 0;
  gcry_sexp_build(r,NULL,"(private-key(rsa(n %b)(e %b)(d %b)(p %b)(q %b)(u %b)))",ntohl(n->size),n->string,ntohl(e->size),e->string,ntohl(d->size),d->string,ntohl(p->size),p->string,ntohl(q->size),q->string,ntohl(u->size),u->string);
  free(n);
  free(e);
  free(d);
  free(p);
  free(q);
  free(unused1);
  free(unused2);
  free(u);
  free(v);
  return 1;
}

static int read_dsa_privatekey(FILE *fp, gcry_sexp_t *r, ssh_auth_callback cb,
    void *userdata, char *desc) {
  STRING *p;
  STRING *q;
  STRING *g;
  STRING *y;
  STRING *x;
  STRING *v;
  BUFFER *buffer;

  if (!(buffer=privatekey_file_to_buffer(fp, TYPE_DSS, cb, userdata, desc)))
    return 0;
  if (!asn1_check_sequence(buffer))
  {
    buffer_free(buffer);
    return 0;
  }
  v=asn1_get_int(buffer);
  if (ntohl(v->size)!=1 || v->string[0]!=0)
  {
    buffer_free(buffer);
    return 0;
  }
  p=asn1_get_int(buffer);
  q=asn1_get_int(buffer);
  g=asn1_get_int(buffer);
  y=asn1_get_int(buffer);
  x=asn1_get_int(buffer);
  buffer_free(buffer);
  if (!p || !q || !g || !y || !x)
    return 0;
  gcry_sexp_build(r,NULL,"(private-key(dsa(p %b)(q %b)(g %b)(y %b)(x %b)))",ntohl(p->size),p->string,ntohl(q->size),q->string,ntohl(g->size),g->string,ntohl(y->size),y->string,ntohl(x->size),x->string);
  free(p);
  free(q);
  free(g);
  free(y);
  free(x);
  free(v);
  return 1;
}
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBCRYPTO
static int pem_get_password(char *buf, int size, int rwflag, void *userdata) {
  SSH_SESSION *session = userdata;

  /* unused flag */
  (void) rwflag;

  ZERO_STRUCTP(buf);

  if (session && session->options->auth_function) {
    if ((*session->options->auth_function)("Passphrase for private key:", buf, size, 0, 0,
        session->options->auth_userdata ? session->options->auth_userdata : NULL) < 0) {
      return 0;
    }

    return strlen(buf);
  }

  return 0;
}
#endif /* HAVE_LIBCRYPTO */

/** \addtogroup ssh_auth
 * @{
 */
/* TODO : implement it to read both DSA and RSA at once */
/** \brief Reads a SSH private key from a file
 * \param session SSH Session
 * \param filename Filename containing the private key
 * \param type Type of the private key. One of TYPE_DSS or TYPE_RSA.
 * \param passphrase Passphrase to decrypt the private key. Set to null if none is needed or it is unknown.
 * \returns a PRIVATE_KEY object containing the private key, or NULL if it failed.
 * \see private_key_free()
 * \see publickey_from_privatekey()
 */
PRIVATE_KEY  *privatekey_from_file(SSH_SESSION *session, const char *filename,
    int type, const char *passphrase) {
    FILE *file=fopen(filename,"r");
    PRIVATE_KEY *privkey;
    ssh_auth_callback auth_cb = NULL;
    void *auth_ud = NULL;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa=NULL;
    gcry_sexp_t rsa=NULL;
    int valid;
#elif defined HAVE_LIBCRYPTO
    DSA *dsa=NULL;
    RSA *rsa=NULL;
#endif
    if(!file){
        ssh_set_error(session,SSH_REQUEST_DENIED,"Error opening %s : %s",filename,strerror(errno));
        return NULL;
    }
    if(type==TYPE_DSS){
        if(!passphrase){
          if (session && session->options->auth_function) {
            auth_cb = session->options->auth_function;
            if (session->options->auth_userdata) {
              auth_ud = session->options->auth_userdata;
            }
#ifdef HAVE_LIBGCRYPT
            valid = read_dsa_privatekey(file,&dsa, auth_cb, auth_ud, "Passphrase for private key:");
          }
        } else {
          valid = read_dsa_privatekey(file,&dsa, NULL, (void *) passphrase, NULL);
        }
        fclose(file);
        if(!valid) {
          ssh_set_error(session,SSH_FATAL,"parsing private key %s",filename);
#elif defined HAVE_LIBCRYPTO
            dsa = PEM_read_DSAPrivateKey(file,NULL, pem_get_password, session);
          } else {
            dsa = PEM_read_DSAPrivateKey(file,NULL, NULL, NULL);
          }
        } else {
          dsa = PEM_read_DSAPrivateKey(file, NULL, NULL, (void *) passphrase);
        }
        fclose(file);
        if(!dsa){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                ": %s",filename,ERR_error_string(ERR_get_error(),NULL));
#endif
        return NULL;
        }
    }
    else if (type==TYPE_RSA){
        if(!passphrase){
            if(session && session->options->auth_function) {
              auth_cb = session->options->auth_function;
              if (session->options->auth_userdata) {
                auth_ud = session->options->auth_userdata;
              }
#ifdef HAVE_LIBGCRYPT
              valid = read_rsa_privatekey(file, &rsa, auth_cb, auth_ud, "Passphrase for private key:");
            }
        } else {
            valid = read_rsa_privatekey(file, &rsa, NULL, (void *) passphrase, NULL);
        }
        fclose(file);
        if(!valid){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s",filename);
#elif defined HAVE_LIBCRYPTO
              rsa = PEM_read_RSAPrivateKey(file, NULL, pem_get_password, session);
            } else {
              rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            }
        } else {
          rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, (void *) passphrase);
        }
        fclose(file);
        if(!rsa){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                ": %s",filename,ERR_error_string(ERR_get_error(),NULL));
#endif
        return NULL;
        }
    } else {
        ssh_set_error(session,SSH_FATAL,"Invalid private key type %d",type);
        return NULL;
    }

    privkey = malloc(sizeof(PRIVATE_KEY));
    if (privkey == NULL) {
      return NULL;
    }
    privkey->type=type;
    privkey->dsa_priv=dsa;
    privkey->rsa_priv=rsa;
    return privkey;
}

/* same that privatekey_from_file() but without any passphrase things. */
PRIVATE_KEY *_privatekey_from_file(void *session, const char *filename,
    int type) {
    FILE *file=fopen(filename,"r");
    PRIVATE_KEY *privkey;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa=NULL;
    gcry_sexp_t rsa=NULL;
    int valid;
#elif defined HAVE_LIBCRYPTO
    DSA *dsa=NULL;
    RSA *rsa=NULL;
#endif
    if(!file){
        ssh_set_error(session,SSH_REQUEST_DENIED,"Error opening %s : %s",filename,strerror(errno));
        return NULL;
    }
    if(type==TYPE_DSS){
#ifdef HAVE_LIBGCRYPT
        valid=read_dsa_privatekey(file,&dsa,NULL,NULL,NULL);
        fclose(file);
        if(!valid){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                    ,filename);
#elif defined HAVE_LIBCRYPTO
        dsa=PEM_read_DSAPrivateKey(file,NULL,NULL,NULL);
        fclose(file);
        if(!dsa){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                    ": %s",filename,ERR_error_string(ERR_get_error(),NULL));
#endif
            return NULL;
        }
    }
    else if (type==TYPE_RSA){
#ifdef HAVE_LIBGCRYPT
        valid=read_rsa_privatekey(file,&rsa,NULL,NULL,NULL);
        fclose(file);
        if(!valid){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                    ,filename);
#elif defined HAVE_LIBCRYPTO
        rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL);
        fclose(file);
        if(!rsa){
            ssh_set_error(session,SSH_FATAL,"parsing private key %s"
                    ": %s",filename,ERR_error_string(ERR_get_error(),NULL));
#endif
            return NULL;
        }
    } else {
        ssh_set_error(session,SSH_FATAL,"Invalid private key type %d",type);
        return NULL;
    }
    privkey = malloc(sizeof(PRIVATE_KEY));
    if (privkey == NULL) {
      return NULL;
    }
    privkey->type=type;
    privkey->dsa_priv=dsa;
    privkey->rsa_priv=rsa;
    return privkey;
}

/** \brief deallocate a private key
 * \param prv a PRIVATE_KEY object
 */
void private_key_free(PRIVATE_KEY *prv) {
  if (prv == NULL) {
    return;
  }

#ifdef HAVE_LIBGCRYPT
  gcry_sexp_release(prv->dsa_priv);
  gcry_sexp_release(prv->rsa_priv);
#elif defined HAVE_LIBCRYPTO
  DSA_free(prv->dsa_priv);
  RSA_free(prv->rsa_priv);
#endif
  memset(prv, 0, sizeof(PRIVATE_KEY));
  SAFE_FREE(prv);
}

/** \brief Retrieve a public key from a file
 * \param session the SSH session
 * \param filename Filename of the key
 * \param _type Pointer to a integer. If it is not null, it contains the type of the key after execution.
 * \return a SSH String containing the public key, or NULL if it failed.
 * \see string_free()
 * \see publickey_from_privatekey()
 */
STRING *publickey_from_file(SSH_SESSION *session, const char *filename,
    int *_type) {
    BUFFER *buffer;
    int type;
    STRING *str;
    char buf[4096]; /* noone will have bigger keys that that */
                        /* where have i head that again ? */
    int fd=open(filename,O_RDONLY);
    int r;
    char *ptr;
    if(fd<0){
        ssh_set_error(session,SSH_REQUEST_DENIED,"nonexistent public key file");
        return NULL;
    }
    if(read(fd,buf,8)!=8){
        close(fd);
        ssh_set_error(session,SSH_REQUEST_DENIED,"Invalid public key file");
        return NULL;
    }
    buf[7]=0;
    if(!strcmp(buf,"ssh-dss"))
        type=TYPE_DSS;
    else if (!strcmp(buf,"ssh-rsa"))
        type=TYPE_RSA;
    else {
        close(fd);
        ssh_set_error(session,SSH_REQUEST_DENIED,"Invalid public key file");
        return NULL;
    }
    r=read(fd,buf,sizeof(buf)-1);
    close(fd);
    if(r<=0){
        ssh_set_error(session,SSH_REQUEST_DENIED,"Invalid public key file");
        return NULL;
    }
    buf[r]=0;
    ptr=strchr(buf,' ');
    if(ptr)
        *ptr=0; /* eliminates the garbage at end of file */
    buffer=base64_to_bin(buf);
    if(buffer){
        str=string_new(buffer_get_len(buffer));
        string_fill(str,buffer_get(buffer),buffer_get_len(buffer));
        buffer_free(buffer);
        if(_type)
            *_type=type;
        return str;
    } else {
        ssh_set_error(session,SSH_REQUEST_DENIED,"Invalid public key file");
        return NULL; /* invalid file */
    }
}


/* why recursing ? i'll explain. on top, publickey_from_next_file will be executed until NULL returned */
/* we can't return null if one of the possible keys is wrong. we must test them before getting over */
STRING *publickey_from_next_file(SSH_SESSION *session, const char **pub_keys_path,
    const char **keys_path, char **privkeyfile, int *type, int *count) {
    static char *home=NULL;
    char public[256];
    char private[256];
    const char *priv;
    const char *pub;
    STRING *pubkey;
    if(!home)
        home=ssh_get_user_home_dir();
    if(home==NULL) {
        ssh_set_error(session,SSH_FATAL,"User home dir impossible to guess");
        return NULL;
    }
    ssh_set_error(session,SSH_REQUEST_DENIED,"no public key matched");
    if((pub=pub_keys_path[*count])==NULL)
        return NULL;
    if((priv=keys_path[*count])==NULL)
        return NULL;
    ++*count;
    /* are them readable ? */
    snprintf(public,256,pub,home);
    ssh_log(session,SSH_LOG_PACKET,"Trying to open public key %s",public);
    if(!ssh_file_readaccess_ok(public)){
        ssh_log(session,SSH_LOG_PACKET,"Failed");
        return publickey_from_next_file(session,pub_keys_path,keys_path,privkeyfile,type,count);
    }
    snprintf(private,256,priv,home);
    ssh_log(session,SSH_LOG_PACKET,"Trying to open private key %s",private);
    if(!ssh_file_readaccess_ok(private)){
        ssh_log(session,SSH_LOG_PACKET,"Failed");
        return publickey_from_next_file(session,pub_keys_path,keys_path,privkeyfile,type,count);
    }
    ssh_log(session,SSH_LOG_PACKET,"Success reading public and private key");
    /* ok, we are sure both the priv8 and public key files are readable : we return the public one as a string,
        and the private filename in arguments */
    pubkey=publickey_from_file(session,public,type);
    if(!pubkey){
        ssh_log(session,SSH_LOG_PACKET,"Wasn't able to open public key file %s : %s",public,ssh_get_error(session));
        return publickey_from_next_file(session,pub_keys_path,keys_path,privkeyfile,type,count);
    }
    *privkeyfile=realloc(*privkeyfile,strlen(private)+1);
    strcpy(*privkeyfile,private);
    return pubkey;
}

static int alldigits(char *s)
{
       while (*s) {
               if (((*s) < '0') || ((*s) > '9')) return 0;
               s++;
       }
       return 1;
}
/** @}
 */
/** \addtogroup ssh_session
 * @{ */

/**
 * \brief Lowercase a string.
 * \param  str          String to lowercase.
 * \return              The malloced lowered string or NULL on error.
 * \internal
 */
static char *lowercase(const char* str) {
  char *p = 0;
  char *new = strdup(str);

  if((str == NULL) || (new == NULL)) {
    return NULL;
  }

  for (p = new; *p; p++) {
    *p = tolower(*p);
  }

  return new;
}

/** \brief frees a token array
 * \internal
 */
static void tokens_free(char **tokens) {
  if (tokens == NULL) {
    return;
  }

  SAFE_FREE(tokens[0]);
  /* It's not needed to free other pointers because tokens generated by
   * space_tokenize fit all in one malloc
   */
  SAFE_FREE(tokens);
}
/** \brief returns one line of known host file
 * will return a token array containing (host|ip) keytype key
 * \param file pointer to the known host file. Could be pointing to NULL at start
 * \param filename file name of the known host file
 * \param found_type pointer to a string to be set with the found key type
 * \internal
 * \returns NULL if no match was found or the file was not found
 * \returns found_type type of key (ie "dsa","ssh-rsa1"). Don't free that value.
 */

static char **ssh_get_knownhost_line(SSH_SESSION *session, FILE **file,
    const char *filename, const char **found_type) {
    char buffer[4096];
    char *ptr;
    char **tokens;
    enter_function();
    if(!*file){
    	*file=fopen(filename,"r");
    	if(!file){
    		leave_function();
    		return NULL;
    	}
    }
    while(fgets(buffer,sizeof(buffer),*file)){
        ptr=strchr(buffer,'\n');
        if(ptr) *ptr=0;
        if((ptr=strchr(buffer,'\r'))) *ptr=0;
        if(!buffer[0] || buffer[0]=='#')
            continue; /* skip empty lines */
        tokens=space_tokenize(buffer);
        if (tokens == NULL) {
          fclose(*file);
          *file = NULL;
          leave_function();
          return NULL;
        }
        if(!tokens[0] || !tokens[1] || !tokens[2]){
            /* it should have at least 3 tokens */
            tokens_free(tokens);
            continue;
        }
        *found_type = tokens[1];
        if(tokens[3]){
           /* openssh rsa1 format has 4 tokens on the line. Recognize it
              by the fact that everything is all digits */
           if (tokens[4]) {
               /* that's never valid */
               tokens_free(tokens);
               continue;
           }
           if (alldigits(tokens[1]) && alldigits(tokens[2]) && alldigits(tokens[3])) {
               *found_type = "ssh-rsa1";
           } else {
               /* 3 tokens only, not four */
               tokens_free(tokens);
               continue;
           }
        }
        leave_function();
        return tokens;
    }
    fclose(*file);
    *file=NULL;
    /* we did not find anything, end of file*/
    leave_function();
    return NULL;
}

/** \brief Check the public key in the known host line matches the
 * public key of the currently connected server.
 * \param tokens list of tokens in the known_hosts line.
 * \return 1 if the key matches
 * \return 0 if the key doesn't match
 * \return -1 on error
 */

static int check_public_key(SSH_SESSION *session, char **tokens){
    char *pubkey_64;
    BUFFER *pubkey_buffer;
    STRING *pubkey=session->current_crypto->server_pubkey;
	/* ok we found some public key in known hosts file. now un-base64it */
	if (alldigits(tokens[1])) {
		/* openssh rsa1 format */
		bignum tmpbn;
		int i;
		unsigned int len;
		STRING *tmpstring;

		pubkey_buffer = buffer_new();
		tmpstring = string_from_char("ssh-rsa1");
		buffer_add_ssh_string(pubkey_buffer, tmpstring);

		for (i = 2; i < 4; i++) { /* e, then n */
			tmpbn = NULL;
			bignum_dec2bn(tokens[i], &tmpbn);
			/* for some reason, make_bignum_string does not work
              because of the padding which it does --kv */
			/* tmpstring = make_bignum_string(tmpbn); */
			/* do it manually instead */
			len = bignum_num_bytes(tmpbn);
			tmpstring = malloc(4 + len);
                        if (tmpstring == NULL) {
                          return -1;
                          ssh_set_error(session, SSH_FATAL, "No space left");
                        }
			tmpstring->size = htonl(len);
#ifdef HAVE_LIBGCRYPT
			bignum_bn2bin(tmpbn, len, tmpstring->string);
#elif defined HAVE_LIBCRYPTO
			bignum_bn2bin(tmpbn, tmpstring->string);
#endif
			bignum_free(tmpbn);
			buffer_add_ssh_string(pubkey_buffer, tmpstring);
			free(tmpstring);
		}
	} else {
		/* ssh-dss or ssh-rsa */
		pubkey_64=tokens[2];
		pubkey_buffer=base64_to_bin(pubkey_64);
	}

	if(!pubkey_buffer){
		ssh_set_error(session,SSH_FATAL,"verifying that server is a known host : base 64 error");
		return -1;
	}
	if(buffer_get_len(pubkey_buffer)!=string_len(pubkey)){
		buffer_free(pubkey_buffer);
		return 0;
	}
	/* now test that they are identical */
	if(memcmp(buffer_get(pubkey_buffer),pubkey->string,buffer_get_len(pubkey_buffer))!=0){
		buffer_free(pubkey_buffer);
		return 0;
	}
	buffer_free(pubkey_buffer);
	return 1;
}

/** \brief checks if a hostname matches a openssh-style hashed known host
 * \param host host to check
 * \param hashed hashed value
 * \returns 1 if it matches
 * \returns 0 otherwise
 */
static int match_hashed_host(SSH_SESSION *session, char *host, char *sourcehash){
	/* Openssh hash structure :
	 * |1|base64 encoded salt|base64 encoded hash
	 * hash is produced that way :
	 * hash := HMAC_SHA1(key=salt,data=host)
	 */
	char *source;
	char *b64hash;
	BUFFER *salt;
	BUFFER *hash;
	HMACCTX mac;
	int match;
	unsigned char buffer[256];
	unsigned int size=sizeof(buffer);

	enter_function();
	if(strncmp(sourcehash,"|1|",3) != 0)
		return 0;
	source=strdup(sourcehash+3);
        if (source == NULL) {
          leave_function();
          return 0;
        }
	b64hash=strchr(source,'|');
	if(!b64hash){
		/* Invalid hash */
		SAFE_FREE(source);
		leave_function();
		return 0;
	}
	*b64hash='\0';
	b64hash++;
	salt=base64_to_bin(source);
	hash=base64_to_bin(b64hash);
	free(source);
	mac=hmac_init(buffer_get(salt),buffer_get_len(salt),HMAC_SHA1);
        if (mac == NULL) {
          SAFE_FREE(source);
          leave_function();
          return 0;
        }
	hmac_update(mac,host,strlen(host));
	hmac_final(mac,buffer,&size);
	if(size == buffer_get_len(hash) && memcmp(buffer,buffer_get(hash),size)==0)
		match=1;
	else
		match=0;
	buffer_free(salt);
	buffer_free(hash);
	ssh_log(session,SSH_LOG_PACKET,"Matching a hashed host : %s match=%d",host,match);
	leave_function();
	return match;
}
/* How it's working :
 * 1- we open the known host file and bitch if it doesn't exist
 * 2- we need to examine each line of the file, until going on state SSH_SERVER_KNOWN_OK:
 *  - there's a match. if the key is good, state is SSH_SERVER_KNOWN_OK,
 *    else it's SSH_SERVER_KNOWN_CHANGED (or SSH_SERVER_FOUND_OTHER)
 *  - there's no match : no change
 */

/** checks the user's known host file for a previous connection to the
 * current server.
 * \brief test if the server is known
 * \param session ssh session
 * \return SSH_SERVER_KNOWN_OK : the server is known and has not changed\n
 * SSH_SERVER_KNOWN_CHANGED : The server key has changed. Either you are under
 * attack or the administrator changed the key. you HAVE to warn the user about
 * a possible attack\n
 * SSH_SERVER_FOUND_OTHER : the server gave use a key of a type while we
 * had an other type recorded. It is a possible attack \n
 * SSH_SERVER_NOT_KNOWN : the server is unknown. User should confirm the MD5 is correct\n
 * SSH_SERVER_ERROR : Some error happened
 * \see ssh_options_set_wanted_algo()
 * \see ssh_get_pubkey_hash()
 * \bug there is no current way to remove or modify an entry into the known host table
 */
int ssh_is_server_known(SSH_SESSION *session){

    char **tokens;
    char *host;
    const char *type;
    int match;
    FILE *file=NULL;
    int ret=SSH_SERVER_NOT_KNOWN;
    enter_function();
    ssh_options_default_known_hosts_file(session->options);
    if(!session->options->host){
        ssh_set_error(session,SSH_FATAL,"Can't verify host in known hosts if the hostname isn't known");
        leave_function();
        return SSH_SERVER_ERROR;
    }
    host = lowercase(session->options->host);
    do {
    	tokens=ssh_get_knownhost_line(session,&file,session->options->known_hosts_file,&type);
    	//
    	/* End of file, return the current state */
    	if(tokens==NULL)
    		break;
    	match=match_hashed_host(session,host,tokens[0]);
    	if(!match)
    		match=match_hostname(host,tokens[0],strlen(tokens[0]));
    	if(match){
    		// We got a match. Now check the key type
    		if(strcmp(session->current_crypto->server_pubkey_type,type)!=0){
    			// different type. We don't override the known_changed error which is more important
    			if(ret != SSH_SERVER_KNOWN_CHANGED)
    				ret= SSH_SERVER_FOUND_OTHER;
    			tokens_free(tokens);
    			continue;
    		}
    		// so we know the key type is good. We may get a good key or a bad key.
			match=check_public_key(session,tokens);
			tokens_free(tokens);
			if(match<0){
				ret = SSH_SERVER_ERROR;
                break;
			}
			if(match==1){
				ret=SSH_SERVER_KNOWN_OK;
                break;
			}
			if(match==0){
				/* We override the status with the wrong key state */
				ret=SSH_SERVER_KNOWN_CHANGED;
			}
    	}
    } while (1);
    SAFE_FREE(host);
	if(file)
        fclose(file);
    /* Return the current state at end of file */
    leave_function();
    return ret;
}

/** You generaly use it when ssh_is_server_known() answered SSH_SERVER_NOT_KNOWN
 * \brief write the current server as known in the known hosts file
 * \param session ssh session
 * \return 0 on success, -1 on error
 */
int ssh_write_knownhost(SSH_SESSION *session){
    unsigned char *pubkey_64;
    STRING *pubkey=session->current_crypto->server_pubkey;
    char buffer[4096];
    size_t len = 0;
    FILE *file;
    ssh_options_default_known_hosts_file(session->options);
    if(!session->options->host){
        ssh_set_error(session,SSH_FATAL,"Cannot write host in known hosts if the hostname is unknown");
        return -1;
    }
    /* a = append only */
    file=fopen(session->options->known_hosts_file,"a");
    if(!file){
        ssh_set_error(session,SSH_FATAL,"Opening known host file %s for appending : %s",
        session->options->known_hosts_file,strerror(errno));
        return -1;
    }
    if (!strcmp(session->current_crypto->server_pubkey_type, "ssh-rsa1")) {
       /* openssh uses a different format for ssh-rsa1 keys.
          Be compatible --kv */
       char *e_string, *n_string;
       bignum e, n;
       PUBLIC_KEY *key = publickey_from_string(session, pubkey);
       int rsa_size;
#ifdef HAVE_LIBGCRYPT
       gcry_sexp_t sexp;
       sexp=gcry_sexp_find_token(key->rsa_pub,"e",0);
       e=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
       gcry_sexp_release(sexp);
       sexp=gcry_sexp_find_token(key->rsa_pub,"n",0);
       n=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
       gcry_sexp_release(sexp);
       rsa_size=(gcry_pk_get_nbits(key->rsa_pub)+7)/8;
#elif defined HAVE_LIBCRYPTO
       e = key->rsa_pub->e;
       n = key->rsa_pub->n;
       rsa_size = RSA_size(key->rsa_pub);
#endif
       e_string = bignum_bn2dec(e);
       n_string = bignum_bn2dec(n);
       snprintf(buffer, sizeof(buffer), "%s %d %s %s\n",
               session->options->host, rsa_size << 3,
               e_string, n_string);
#ifdef HAVE_LIBGCRYPT
       free(e_string);
       gcry_mpi_release(e);
       free(n_string);
       gcry_mpi_release(n);
#elif defined HAVE_LIBCRYPTO
       OPENSSL_free(e_string);
       OPENSSL_free(n_string);
#endif
       free(key);
    } else {
       pubkey_64=bin_to_base64(pubkey->string,string_len(pubkey));
       snprintf(buffer,sizeof(buffer),"%s %s %s\n",session->options->host,session->current_crypto->server_pubkey_type,pubkey_64);
       free(pubkey_64);
    }
    len = strlen(buffer);
    if (fwrite(buffer, len, 1, file) != len || ferror(file)) {
      fclose(file);
      return -1;
    }
    fclose(file);
    return 0;
}

/** @} */

