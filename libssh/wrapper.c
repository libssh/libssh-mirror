/* wrapper.c */
/* wrapping functions for crypto functions. */
/* why a wrapper ? let's say you want to port libssh from libcrypto of openssl to libfoo */
/* you are going to spend hours to remove every references to SHA1_Update() to libfoo_sha1_update */
/* after the work is finished, you're going to have only this file to modify */
/* it's not needed to say that your modifications are welcome */

/*
Copyright 2003 Aris Adamantiadis

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

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>

SHACTX sha1_init(){
    SHACTX ret;
    gcry_md_open(&ret,GCRY_MD_SHA1,0);
    return ret;
}
void sha1_update(SHACTX c, const void *data, unsigned long len){
    gcry_md_write(c,data,len);
}
void sha1_final(unsigned char *md,SHACTX c){
    gcry_md_final(c);
    memcpy(md, gcry_md_read(c, 0), SHA_DIGEST_LEN);
    gcry_md_close(c);
}
void sha1(unsigned char *digest,int len,unsigned char *hash){
    gcry_md_hash_buffer(GCRY_MD_SHA1,hash,digest,len);
}

MD5CTX md5_init(){
    MD5CTX ret;
    gcry_md_open(&ret,GCRY_MD_MD5,0);
    return ret;
}
void md5_update(MD5CTX c, const void *data, unsigned long len){
    gcry_md_write(c,data,len);
}
void md5_final(unsigned char *md,MD5CTX c){
    gcry_md_final(c);
    memcpy(md, gcry_md_read(c, 0), MD5_DIGEST_LEN);
    gcry_md_close(c);
}

HMACCTX hmac_init(const void *key, int len,int type){
    HMACCTX c;
    switch(type){
        case HMAC_SHA1:
            gcry_md_open(&c,GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
            break;
        case HMAC_MD5:
            gcry_md_open(&c,GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
            break;
        default:
            c=NULL;
        }
    gcry_md_setkey(c,key,len);
    return c;
}
void hmac_update(HMACCTX c, const void *data, unsigned long len){
    gcry_md_write(c,data,len);
}

void hmac_final(HMACCTX c,unsigned char *hashmacbuf,unsigned int *len){
    *len = gcry_md_get_algo_dlen(gcry_md_get_algo(c));
    memcpy(hashmacbuf, gcry_md_read(c, 0), *len);
    gcry_md_close(c);
}

static void alloc_key(struct crypto_struct *cipher){
    cipher->key=malloc(cipher->keylen);
}

/* the wrapper functions for blowfish */
static void blowfish_set_key(struct crypto_struct *cipher, void *key, void *IV){
    if(!cipher->key){
        alloc_key(cipher);
        gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_BLOWFISH,GCRY_CIPHER_MODE_CBC,0);
        gcry_cipher_setkey(cipher->key[0],key,16);
        gcry_cipher_setiv(cipher->key[0],IV,8);
    }
}

static void blowfish_encrypt(struct crypto_struct *cipher, void *in, void *out,unsigned long len){
    gcry_cipher_encrypt(cipher->key[0],out,len,in,len);
}

static void blowfish_decrypt(struct crypto_struct *cipher, void *in, void *out, unsigned long len){
    gcry_cipher_decrypt(cipher->key[0],out,len,in,len);
}

static void aes_set_key(struct crypto_struct *cipher, void *key, void *IV){
    if(!cipher->key){
        alloc_key(cipher);
        switch(cipher->keysize){
          case 128:
            gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC,0);
            break;
          case 192:
            gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_AES192,GCRY_CIPHER_MODE_CBC,0);
            break;
          case 256:
            gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CBC,0);
            break;
        }
        gcry_cipher_setkey(cipher->key[0],key,cipher->keysize/8);
        gcry_cipher_setiv(cipher->key[0], IV, 16);
    }
}

static void aes_encrypt(struct crypto_struct *cipher, void *in, void *out, unsigned long len){
    gcry_cipher_encrypt(cipher->key[0],out,len,in,len);
}

static void aes_decrypt(struct crypto_struct *cipher, void *in, void *out,unsigned long len){
    gcry_cipher_decrypt(cipher->key[0],out,len,in,len);
}

static void des3_set_key(struct crypto_struct *cipher, void *key, void *IV){
    if(!cipher->key){
        alloc_key(cipher);
        gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_3DES,GCRY_CIPHER_MODE_CBC,0);
        gcry_cipher_setkey(cipher->key[0],key,24);
        gcry_cipher_setiv(cipher->key[0],IV,8);
    }
}

static void des3_encrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len){
    gcry_cipher_encrypt(cipher->key[0],out,len,in,len);
}

static void des3_decrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len){
    gcry_cipher_decrypt(cipher->key[0],out,len,in,len);
}

static void des3_1_set_key(struct crypto_struct *cipher, void *key, void *IV){
    if(!cipher->key){
        alloc_key(cipher);
        gcry_cipher_open(&cipher->key[0],GCRY_CIPHER_DES,GCRY_CIPHER_MODE_CBC,0);
        gcry_cipher_setkey(cipher->key[0],key,8);
        gcry_cipher_setiv(cipher->key[0],IV,8);
        gcry_cipher_open(&cipher->key[1],GCRY_CIPHER_DES,GCRY_CIPHER_MODE_CBC,0);
        gcry_cipher_setkey(cipher->key[1],key+8,8);
        gcry_cipher_setiv(cipher->key[1],IV+8,8);
        gcry_cipher_open(&cipher->key[2],GCRY_CIPHER_DES,GCRY_CIPHER_MODE_CBC,0);
        gcry_cipher_setkey(cipher->key[2],key+16,8);
        gcry_cipher_setiv(cipher->key[2],IV+16,8);
    }
}

static void des3_1_encrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len){
    gcry_cipher_encrypt(cipher->key[0],out,len,in,len);
    gcry_cipher_decrypt(cipher->key[1],in,len,out,len);
    gcry_cipher_encrypt(cipher->key[2],out,len,in,len);
}

static void des3_1_decrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len){
    gcry_cipher_decrypt(cipher->key[2],out,len,in,len);
    gcry_cipher_encrypt(cipher->key[1],in,len,out,len);
    gcry_cipher_decrypt(cipher->key[0],out,len,in,len);
}

/* the table of supported ciphers */
static struct crypto_struct ssh_ciphertab[]={
    { "blowfish-cbc", 8 ,sizeof (gcry_cipher_hd_t),NULL,128,blowfish_set_key,blowfish_set_key,blowfish_encrypt, blowfish_decrypt},
    { "aes128-cbc",16,sizeof(gcry_cipher_hd_t),NULL,128,aes_set_key,aes_set_key,aes_encrypt,aes_decrypt},
    { "aes192-cbc",16,sizeof(gcry_cipher_hd_t),NULL,192,aes_set_key,aes_set_key,aes_encrypt,aes_decrypt},
    { "aes256-cbc",16,sizeof(gcry_cipher_hd_t),NULL,256,aes_set_key,aes_set_key,aes_encrypt,aes_decrypt},
    { "3des-cbc",8,sizeof(gcry_cipher_hd_t),NULL,192,des3_set_key, 
        des3_set_key,des3_encrypt, des3_decrypt},
    { "3des-cbc-ssh1",8,sizeof(gcry_cipher_hd_t)*3,NULL,192,des3_1_set_key, 
        des3_1_set_key,des3_1_encrypt, des3_1_decrypt},
    { NULL,0,0,NULL,0,NULL,NULL,NULL}
};
#elif defined HAVE_LIBCRYPTO
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#ifdef HAVE_OPENSSL_AES_H
#define HAS_AES
#include <openssl/aes.h>
#endif
#ifdef HAVE_OPENSSL_BLOWFISH_H
#define HAS_BLOWFISH
#include <openssl/blowfish.h>
#endif
#ifdef HAVE_OPENSSL_DES_H
#define HAS_DES
#include <openssl/des.h>
#endif

#if (OPENSSL_VERSION_NUMBER<0x009070000)
#define OLD_CRYPTO
#endif

SHACTX sha1_init(){
    SHACTX c=malloc(sizeof(*c));
    SHA1_Init(c);
    return c;
}
void sha1_update(SHACTX c, const void *data, unsigned long len){
    SHA1_Update(c,data,len);
}
void sha1_final(unsigned char *md,SHACTX c){
    SHA1_Final(md,c);
    free(c);
}
void sha1(unsigned char *digest,int len,unsigned char *hash){
    SHA1(digest,len,hash);
}

MD5CTX md5_init(){
    MD5CTX c=malloc(sizeof(*c));
    MD5_Init(c);
    return c;
}
void md5_update(MD5CTX c, const void *data, unsigned long len){
    MD5_Update(c,data,len);
}
void md5_final(unsigned char *md,MD5CTX c){
    MD5_Final(md,c);
    free(c);
}

HMACCTX hmac_init(const void *key, int len,int type){
    HMACCTX ctx;
    ctx=malloc(sizeof(*ctx));
#ifndef OLD_CRYPTO
    HMAC_CTX_init(ctx); // openssl 0.9.7 requires it.
#endif
    switch(type){
        case HMAC_SHA1:
            HMAC_Init(ctx,key,len,EVP_sha1());
            break;
        case HMAC_MD5:
            HMAC_Init(ctx,key,len,EVP_md5());
            break;
        default:
            free(ctx);
            ctx=NULL;
        }
    return ctx;
}
void hmac_update(HMACCTX ctx,const void *data, unsigned long len){
    HMAC_Update(ctx,data,len);
}
void hmac_final(HMACCTX ctx,unsigned char *hashmacbuf,unsigned int *len){
   HMAC_Final(ctx,hashmacbuf,len);
#ifndef OLD_CRYPTO
   HMAC_CTX_cleanup(ctx);
#else
   HMAC_cleanup(ctx);
#endif
   free(ctx);
}

static void alloc_key(struct crypto_struct *cipher){
    cipher->key=malloc(cipher->keylen);
}

#ifdef HAS_BLOWFISH
/* the wrapper functions for blowfish */
static void blowfish_set_key(struct crypto_struct *cipher, void *key){
    if(!cipher->key){
        alloc_key(cipher);
        BF_set_key(cipher->key,16,key);
    }
}

static void blowfish_encrypt(struct crypto_struct *cipher, void *in, void *out,unsigned long len,void *IV){
    BF_cbc_encrypt(in,out,len,cipher->key,IV,BF_ENCRYPT);
}

static void blowfish_decrypt(struct crypto_struct *cipher, void *in, void *out,unsigned long len,void *IV){
    BF_cbc_encrypt(in,out,len,cipher->key,IV,BF_DECRYPT);
}
#endif
#ifdef HAS_AES
static void aes_set_encrypt_key(struct crypto_struct *cipher, void *key){
    if(!cipher->key){
        alloc_key(cipher);
        AES_set_encrypt_key(key,cipher->keysize,cipher->key);
    }
}
static void aes_set_decrypt_key(struct crypto_struct *cipher, void *key){
    if(!cipher->key){
        alloc_key(cipher);
        AES_set_decrypt_key(key,cipher->keysize,cipher->key);
    }
}
static void aes_encrypt(struct crypto_struct *cipher, void *in, void *out, unsigned long len, void *IV){
    AES_cbc_encrypt(in,out,len,cipher->key,IV,AES_ENCRYPT);
}
static void aes_decrypt(struct crypto_struct *cipher, void *in, void *out, unsigned long len, void *IV){
    AES_cbc_encrypt(in,out,len,cipher->key,IV,AES_DECRYPT);
}
#endif
#ifdef HAS_DES
static void des3_set_key(struct crypto_struct *cipher, void *key){
    if(!cipher->key){
        alloc_key(cipher);
        DES_set_odd_parity(key);
        DES_set_odd_parity(key+8);
        DES_set_odd_parity(key+16);
        DES_set_key_unchecked(key,cipher->key);
        DES_set_key_unchecked(key+8,cipher->key+sizeof(DES_key_schedule));
        DES_set_key_unchecked(key+16,cipher->key+2*sizeof(DES_key_schedule));
    }
}

static void des3_encrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len, void *IV){
    DES_ede3_cbc_encrypt(in,out,len,cipher->key,cipher->key+sizeof(DES_key_schedule),cipher->key+2*sizeof(DES_key_schedule),IV,1);
}

static void des3_decrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len, void *IV){
    DES_ede3_cbc_encrypt(in,out,len,cipher->key,cipher->key+sizeof(DES_key_schedule),cipher->key+2*sizeof(DES_key_schedule),IV,0);
}

static void des3_1_encrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len, void *IV){
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("encrypt IV before",IV,24);
#endif
    DES_ncbc_encrypt(in,out,len, cipher->key, IV, 1);
    DES_ncbc_encrypt(out,in,len, cipher->key + sizeof(DES_key_schedule),
            IV+8,0);
    DES_ncbc_encrypt(in,out,len, cipher->key + 2*sizeof(DES_key_schedule),
            IV+16,1);
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("encrypt IV after",IV,24);
#endif
}

static void des3_1_decrypt(struct crypto_struct *cipher, void *in, void *out, 
        unsigned long len, void *IV){
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("decrypt IV before",IV,24);
#endif
    DES_ncbc_encrypt(in,out,len, cipher->key + 2*sizeof(DES_key_schedule),
            IV, 0);
    DES_ncbc_encrypt(out,in,len, cipher->key + sizeof(DES_key_schedule),
            IV+8,1);
    DES_ncbc_encrypt(in,out,len, cipher->key,
            IV+16,0);
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("decrypt IV after",IV,24);
#endif
}
#endif

/* the table of supported ciphers */
static struct crypto_struct ssh_ciphertab[]={
#ifdef HAS_BLOWFISH
    { "blowfish-cbc", 8 ,sizeof (BF_KEY),NULL,128,blowfish_set_key,
        blowfish_set_key,blowfish_encrypt, blowfish_decrypt},
#endif
#ifdef HAS_AES
    { "aes128-cbc",16,sizeof(AES_KEY),NULL,128,aes_set_encrypt_key,
        aes_set_decrypt_key,aes_encrypt,aes_decrypt},
    { "aes192-cbc",16,sizeof(AES_KEY),NULL,192,aes_set_encrypt_key,
        aes_set_decrypt_key,aes_encrypt,aes_decrypt},
    { "aes256-cbc",16,sizeof(AES_KEY),NULL,256,aes_set_encrypt_key,
        aes_set_decrypt_key,aes_encrypt,aes_decrypt},
#endif
#ifdef HAS_DES
    { "3des-cbc",8,sizeof(DES_key_schedule)*3,NULL,192,des3_set_key, 
        des3_set_key,des3_encrypt, des3_decrypt},
    { "3des-cbc-ssh1",8,sizeof(DES_key_schedule)*3,NULL,192,des3_set_key, 
        des3_set_key,des3_1_encrypt, des3_1_decrypt},
#endif
     { NULL,0,0,NULL,0,NULL,NULL,NULL}
};
#endif /* OPENSSL_CRYPTO */

/* it allocates a new cipher structure based on its offset into the global table */
struct crypto_struct *cipher_new(int offset){
    struct crypto_struct *cipher=malloc(sizeof(struct crypto_struct));
    /* note the memcpy will copy the pointers : so, you shouldn't free them */
    memcpy(cipher,&ssh_ciphertab[offset],sizeof(*cipher));
    return cipher;
}

void cipher_free(struct crypto_struct *cipher){
#ifdef HAVE_LIBGCRYPT
    int i;
#endif
    if(cipher->key){
#ifdef HAVE_LIBGCRYPT
        for (i=0;i<cipher->keylen/sizeof (gcry_cipher_hd_t);i++)
          gcry_cipher_close(cipher->key[i]);
#elif defined HAVE_LIBCRYPTO
        /* destroy the key */
        memset(cipher->key,0,cipher->keylen);
#endif
        free(cipher->key);
    }
    free(cipher);
}

CRYPTO *crypto_new(){
    CRYPTO *crypto=malloc(sizeof (CRYPTO));
    memset(crypto,0,sizeof(*crypto));
    return crypto;
}

void crypto_free(CRYPTO *crypto){
    if(crypto->server_pubkey)
        free(crypto->server_pubkey);
    if(crypto->in_cipher)
        cipher_free(crypto->in_cipher);
    if(crypto->out_cipher)
        cipher_free(crypto->out_cipher);
    if(crypto->e)
        bignum_free(crypto->e);
    if(crypto->f)
        bignum_free(crypto->f);
    if(crypto->x)
        bignum_free(crypto->x);
    if(crypto->k)
        bignum_free(crypto->k);
    /* lot of other things */
    /* i'm lost in my own code. good work */
    memset(crypto,0,sizeof(*crypto));
    free(crypto);
}

static int crypt_set_algorithms2(SSH_SESSION *session){
    /* we must scan the kex entries to find crypto algorithms and set their appropriate structure */
    int i=0;
    /* out */
    char *wanted=session->client_kex.methods[SSH_CRYPT_C_S];
    while(ssh_ciphertab[i].name && strcmp(wanted,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms : no crypto algorithm function found for %s",wanted);
        return -1;
    }
    ssh_say(2,"Set output algorithm %s\n",wanted);
    session->next_crypto->out_cipher=cipher_new(i);
    i=0;
    /* in */
    wanted=session->client_kex.methods[SSH_CRYPT_S_C];
    while(ssh_ciphertab[i].name && strcmp(wanted,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms : no crypto algorithm function found for %s",wanted);
        return -1;
    }
    ssh_say(2,"Set input algorithm %s\n",wanted);
    session->next_crypto->in_cipher=cipher_new(i);
    /* compression */
    if(strstr(session->client_kex.methods[SSH_COMP_C_S],"zlib"))
        session->next_crypto->do_compress_out=1;
    if(strstr(session->client_kex.methods[SSH_COMP_S_C],"zlib"))
        session->next_crypto->do_compress_in=1;
    return 0;
}

static int crypt_set_algorithms1(SSH_SESSION *session){
    int i=0;
    /* right now, we force 3des-cbc to be taken */
    while(ssh_ciphertab[i].name && strcmp(ssh_ciphertab[i].name,"3des-cbc-ssh1"))
        ++i;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(NULL,SSH_FATAL,"cipher 3des-cbc-ssh1 not found !");
        return -1;
    }
    session->next_crypto->out_cipher=cipher_new(i);
    session->next_crypto->in_cipher=cipher_new(i);
    return 0;
}

int crypt_set_algorithms(SSH_SESSION *session){
    return session->version==1?crypt_set_algorithms1(session):
        crypt_set_algorithms2(session);
}

int crypt_set_algorithms_server(SSH_SESSION *session){
    /* we must scan the kex entries to find crypto algorithms and set their appropriate structure */
    int i=0;
    /* out */
    char *server=session->server_kex.methods[SSH_CRYPT_S_C];
    char *client=session->client_kex.methods[SSH_CRYPT_S_C];
    char *match=ssh_find_matching(client,server);
    while(ssh_ciphertab[i].name && strcmp(match,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms : no crypto algorithm function found for %s",server);
        return -1;
    }
    ssh_say(2,"Set output algorithm %s\n",match);
    session->next_crypto->out_cipher=cipher_new(i);
    i=0;
    /* in */
    client=session->client_kex.methods[SSH_CRYPT_C_S];
    server=session->server_kex.methods[SSH_CRYPT_S_C];
    match=ssh_find_matching(client,server); 
    while(ssh_ciphertab[i].name && strcmp(match,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms : no crypto algorithm function found for %s",server);
        return -1;
    }
    ssh_say(2,"Set input algorithm %s\n",match);
    session->next_crypto->in_cipher=cipher_new(i);
    /* compression */
    client=session->client_kex.methods[SSH_CRYPT_C_S];
    server=session->server_kex.methods[SSH_CRYPT_C_S];
    match=ssh_find_matching(client,server);
    if(match && !strcmp(match,"zlib")){
        ssh_say(2,"enabling C->S compression\n");
        session->next_crypto->do_compress_in=1;
    }
    
    client=session->client_kex.methods[SSH_CRYPT_S_C];
    server=session->server_kex.methods[SSH_CRYPT_S_C];
    match=ssh_find_matching(client,server);
    if(match && !strcmp(match,"zlib")){
        ssh_say(2,"enabling S->C compression\n");
        session->next_crypto->do_compress_out=1;
    }

    server=session->server_kex.methods[SSH_HOSTKEYS];
    client=session->client_kex.methods[SSH_HOSTKEYS];
    match=ssh_find_matching(client,server);
    if(!strcmp(match,"ssh-dss"))
        session->hostkeys=TYPE_DSS;
    else if(!strcmp(match,"ssh-rsa"))
        session->hostkeys=TYPE_RSA;
    else {
        ssh_set_error(session,SSH_FATAL,"cannot know what %s is into %s",match,server);
        return -1;
    }
    return 0;
}
