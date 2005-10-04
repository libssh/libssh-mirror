/* keys handle the public key related functions */
/* decoding a public key (both rsa and dsa), decoding a signature (rsa and dsa), veryfying them */

/*
Copyright 2003-2005 Aris Adamantiadis

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
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#endif
#include "libssh/priv.h"


/* Public key decoding functions */

char *ssh_type_to_char(int type){
    switch(type){
        case TYPE_DSS:
            return "ssh-dss";
        case TYPE_RSA:
        case TYPE_RSA1:
            return "ssh-rsa";
        default:
            return NULL;
    }
}

PUBLIC_KEY *publickey_make_dss(BUFFER *buffer){
    STRING *p,*q,*g,*pubkey;
    PUBLIC_KEY *key=malloc(sizeof(PUBLIC_KEY));
    key->type=TYPE_DSS;
    key->type_c="ssh-dss";
    p=buffer_get_ssh_string(buffer);
    q=buffer_get_ssh_string(buffer);
    g=buffer_get_ssh_string(buffer);
    pubkey=buffer_get_ssh_string(buffer);
    buffer_free(buffer); /* we don't need it anymore */
    if(!p || !q || !g || !pubkey){
        ssh_set_error(NULL,SSH_FATAL,"Invalid DSA public key");
        if(p)
            free(p);
        if(q)
            free(q);
        if(g)
            free(g);
        if(pubkey)
            free(pubkey);
        free(key);
        return NULL;
    }
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_build(&key->dsa_pub,NULL,"(public-key(dsa(p %b)(q %b)(g %b)(y %b)))",string_len(p),p->string,string_len(q),q->string,string_len(g),g->string,string_len(pubkey),pubkey->string);
#elif defined HAVE_LIBCRYPTO
    key->dsa_pub=DSA_new();
    key->dsa_pub->p=make_string_bn(p);
    key->dsa_pub->q=make_string_bn(q);
    key->dsa_pub->g=make_string_bn(g);
    key->dsa_pub->pub_key=make_string_bn(pubkey);
#endif
    free(p);
    free(q);
    free(g);
    free(pubkey);
    return key;
}

PUBLIC_KEY *publickey_make_rsa(BUFFER *buffer, char *type){
    STRING *e,*n;
    PUBLIC_KEY *key=malloc(sizeof(PUBLIC_KEY));
    if(!strcmp(type,"ssh-rsa"))
        key->type=TYPE_RSA;
    else
        key->type=TYPE_RSA1;
    key->type_c=type;
    e=buffer_get_ssh_string(buffer);
    n=buffer_get_ssh_string(buffer);
    buffer_free(buffer); /* we don't need it anymore */
    if(!e || !n){
        ssh_set_error(NULL,SSH_FATAL,"Invalid RSA public key");
        if(e)
            free(e);
        if(n)
            free(n);
        free(key);
        return NULL;
    }
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_build(&key->rsa_pub,NULL,"(public-key(rsa(n %b)(e %b)))",string_len(n),n->string,string_len(e),e->string);
#elif HAVE_LIBCRYPTO
    key->rsa_pub=RSA_new();
    key->rsa_pub->e=make_string_bn(e);
    key->rsa_pub->n=make_string_bn(n);
#endif
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("e",e->string,string_len(e));
    ssh_print_hexa("n",n->string,string_len(n));
#endif
    free(e);
    free(n);
    return key;
}

void publickey_free(PUBLIC_KEY *key){
    if(!key)
        return;
    switch(key->type){
        case TYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(key->dsa_pub);
#elif HAVE_LIBCRYPTO
            DSA_free(key->dsa_pub);
#endif
            break;
        case TYPE_RSA:
        case TYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(key->rsa_pub);
#elif defined HAVE_LIBCRYPTO
            RSA_free(key->rsa_pub);
#endif
            break;
        default:
            break;
    }
    free(key);
}

PUBLIC_KEY *publickey_from_string(STRING *pubkey_s){
    BUFFER *tmpbuf=buffer_new();
    STRING *type_s;
    char *type;

    buffer_add_data(tmpbuf,pubkey_s->string,string_len(pubkey_s));
    type_s=buffer_get_ssh_string(tmpbuf);
    if(!type_s){
        buffer_free(tmpbuf);
        ssh_set_error(NULL,SSH_FATAL,"Invalid public key format");
        return NULL;
    }
    type=string_to_char(type_s);
    free(type_s);
    if(!strcmp(type,"ssh-dss")){
        free(type);
        return publickey_make_dss(tmpbuf);
    }
    if(!strcmp(type,"ssh-rsa")){
        free(type);
        return publickey_make_rsa(tmpbuf,"ssh-rsa");
    }
    if(!strcmp(type,"ssh-rsa1")){
        free(type);
        return publickey_make_rsa(tmpbuf,"ssh-rsa1");
    }
    ssh_set_error(NULL,SSH_FATAL,"unknown public key protocol %s",type);
    buffer_free(tmpbuf);
    free(type);
    return NULL;
}

PUBLIC_KEY *publickey_from_privatekey(PRIVATE_KEY *prv){
    PUBLIC_KEY *key=malloc(sizeof(PUBLIC_KEY));
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t sexp;
    const char *tmp;
    size_t size;
    STRING *p,*q,*g,*y,*e,*n;
#endif
    key->type=prv->type;
    switch(key->type){
        case TYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            sexp=gcry_sexp_find_token(prv->dsa_priv,"p",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            p=string_new(size);
            string_fill(p,(char *)tmp,size);
            gcry_sexp_release(sexp);
            sexp=gcry_sexp_find_token(prv->dsa_priv,"q",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            q=string_new(size);
            string_fill(q,(char *)tmp,size);
            gcry_sexp_release(sexp);
            sexp=gcry_sexp_find_token(prv->dsa_priv,"g",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            g=string_new(size);
            string_fill(g,(char *)tmp,size);
            gcry_sexp_release(sexp);
            sexp=gcry_sexp_find_token(prv->dsa_priv,"y",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            y=string_new(size);
            string_fill(y,(char *)tmp,size);
            gcry_sexp_release(sexp);
            gcry_sexp_build(&key->dsa_pub,NULL,"(public-key(dsa(p %b)(q %b)(g %b)(y %b)))",string_len(p),p->string,string_len(q),q->string,string_len(g),g->string,string_len(y),y->string);
            free(p);
            free(q);
            free(g);
            free(y);
#elif defined HAVE_LIBCRYPTO
            key->dsa_pub=DSA_new();
            key->dsa_pub->p=BN_dup(prv->dsa_priv->p);
            key->dsa_pub->q=BN_dup(prv->dsa_priv->q);
            key->dsa_pub->pub_key=BN_dup(prv->dsa_priv->pub_key);
            key->dsa_pub->g=BN_dup(prv->dsa_priv->g);
#endif
            break;
        case TYPE_RSA:
        case TYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
            sexp=gcry_sexp_find_token(prv->rsa_priv,"n",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            n=string_new(size);
            string_fill(n,(char *)tmp,size);
            gcry_sexp_release(sexp);
            sexp=gcry_sexp_find_token(prv->rsa_priv,"e",0);
            tmp=gcry_sexp_nth_data(sexp,1,&size);
            e=string_new(size);
            string_fill(e,(char *)tmp,size);
            gcry_sexp_release(sexp);
            gcry_sexp_build(&key->rsa_pub,NULL,"(public-key(rsa(n %b)(e %b)))",string_len(n),n->string,string_len(e),e->string);
            free(e);
            free(n);
#elif defined HAVE_LIBCRYPTO
            key->rsa_pub=RSA_new();
            key->rsa_pub->e=BN_dup(prv->rsa_priv->e);
            key->rsa_pub->n=BN_dup(prv->rsa_priv->n);
#endif
            break;
    }
    key->type_c=ssh_type_to_char(prv->type);
    return key;
}

#ifdef HAVE_LIBGCRYPT
static void dsa_public_to_string(gcry_sexp_t key, BUFFER *buffer){
#elif defined HAVE_LIBCRYPTO
static void dsa_public_to_string(DSA *key, BUFFER *buffer){
#endif
    STRING *p,*q,*g,*n;
#ifdef HAVE_LIBGCRYPT
    const char *tmp;
    size_t size;
    gcry_sexp_t sexp;
    sexp=gcry_sexp_find_token(key,"p",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    p=string_new(size);
    string_fill(p,(char *)tmp,size);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(key,"q",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    q=string_new(size);
    string_fill(q,(char *)tmp,size);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(key,"g",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    g=string_new(size);
    string_fill(g,(char *)tmp,size);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(key,"y",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    n=string_new(size);
    string_fill(n,(char *)tmp,size);
    gcry_sexp_release(sexp);
#elif defined HAVE_LIBCRYPTO
    p=make_bignum_string(key->p);
    q=make_bignum_string(key->q);
    g=make_bignum_string(key->g);
    n=make_bignum_string(key->pub_key);
#endif
    buffer_add_ssh_string(buffer,p);
    buffer_add_ssh_string(buffer,q);
    buffer_add_ssh_string(buffer,g);
    buffer_add_ssh_string(buffer,n);
    free(p);
    free(q);
    free(g);
    free(n);
}

#ifdef HAVE_LIBGCRYPT
static void rsa_public_to_string(gcry_sexp_t key, BUFFER *buffer){
#elif defined HAVE_LIBCRYPTO
static void rsa_public_to_string(RSA *key, BUFFER *buffer){
#endif
    STRING *e, *n;
#ifdef HAVE_LIBGCRYPT
    const char *tmp;
    size_t size;
    gcry_sexp_t sexp;
    sexp=gcry_sexp_find_token(key,"n",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    n=string_new(size);
    string_fill(n,(char *)tmp,size);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(key,"e",0);
    tmp=gcry_sexp_nth_data(sexp,1,&size);
    e=string_new(size);
    string_fill(e,(char *)tmp,size);
    gcry_sexp_release(sexp);
#elif defined HAVE_LIBCRYPTO
    e=make_bignum_string(key->e);
    n=make_bignum_string(key->n);
#endif
    buffer_add_ssh_string(buffer,e);
    buffer_add_ssh_string(buffer,n);
    free(e);
    free(n);
}

STRING *publickey_to_string(PUBLIC_KEY *key){
    STRING *type;
    STRING *ret;
    BUFFER *buf;
    type=string_from_char(ssh_type_to_char(key->type));
    buf=buffer_new();
    buffer_add_ssh_string(buf,type);
    switch(key->type){
        case TYPE_DSS:
            dsa_public_to_string(key->dsa_pub,buf);
            break;
        case TYPE_RSA:
        case TYPE_RSA1:
            rsa_public_to_string(key->rsa_pub,buf);
            break;
    }
    ret=string_new(buffer_get_len(buf));
    string_fill(ret,buffer_get(buf),buffer_get_len(buf));
    buffer_free(buf);
    free(type);
    return ret;
}

/* Signature decoding functions */

STRING *signature_to_string(SIGNATURE *sign){
    STRING *str;
    STRING *rs;
#ifdef HAVE_LIBGCRYPT
    const char *r,*s;
    gcry_sexp_t sexp;
    size_t size;
#elif defined HAVE_LIBCRYPTO
    STRING *r,*s;
#endif
    unsigned char buffer[40];
    BUFFER *tmpbuf=buffer_new();
    STRING *tmp;
    tmp=string_from_char(ssh_type_to_char(sign->type));
    buffer_add_ssh_string(tmpbuf,tmp);
    free(tmp);
    switch(sign->type){
        case TYPE_DSS:
            memset(buffer,0,40);
#ifdef HAVE_LIBGCRYPT
            sexp=gcry_sexp_find_token(sign->dsa_sign,"r",0);
            r=gcry_sexp_nth_data(sexp,1,&size);
            if (*r == 0)      /* libgcrypt put 0 when first bit is set */
            {
              size--;
              r++;
            }
            memcpy(buffer,r + size - 20,20);
            gcry_sexp_release(sexp);
            sexp=gcry_sexp_find_token(sign->dsa_sign,"s",0);
            s=gcry_sexp_nth_data(sexp,1,&size);
            if (*s == 0)
            {
              size--;
              s++;
            }
            memcpy(buffer+ 20, s + size - 20, 20);
            gcry_sexp_release(sexp);
#elif defined HAVE_LIBCRYPTO
            r=make_bignum_string(sign->dsa_sign->r);
            s=make_bignum_string(sign->dsa_sign->s);
            rs=string_new(40);
            memcpy(buffer,r->string+string_len(r)-20,20);
            memcpy(buffer+ 20, s->string + string_len(s) - 20, 20);
            free(r);
            free(s);
#endif
            rs=string_new(40);
            string_fill(rs,buffer,40);
            buffer_add_ssh_string(tmpbuf,rs);
            free(rs);
            break;
        case TYPE_RSA:
        case TYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
            sexp=gcry_sexp_find_token(sign->rsa_sign,"s",0);
            s=gcry_sexp_nth_data(sexp,1,&size);
            if (*s == 0)
            {
              size--;
              s++;
            }
            rs=string_new(size);
            string_fill(rs,(char *)s,size);
            buffer_add_ssh_string(tmpbuf,rs);
            gcry_sexp_release(sexp);
            free(rs);
#elif defined HAVE_LIBCRYPTO
            buffer_add_ssh_string(tmpbuf,sign->rsa_sign);
#endif 
            break;
    }
    str=string_new(buffer_get_len(tmpbuf));
    string_fill(str,buffer_get(tmpbuf),buffer_get_len(tmpbuf));
    buffer_free(tmpbuf);
    return str;
}

/* TODO : split this function in two so it becomes smaller */
SIGNATURE *signature_from_string(STRING *signature,PUBLIC_KEY *pubkey,int needed_type){
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t sig;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *sig;
    STRING *r,*s;
#endif
    SIGNATURE *sign=malloc(sizeof(SIGNATURE));
    BUFFER *tmpbuf=buffer_new();
    STRING *rs;
    STRING *type_s,*e;
    int len,rsalen;
    char *type;
    buffer_add_data(tmpbuf,signature->string,string_len(signature));
    type_s=buffer_get_ssh_string(tmpbuf);
    if(!type_s){
        ssh_set_error(NULL,SSH_FATAL,"Invalid signature packet");
        buffer_free(tmpbuf);
        return NULL;
    }
    type=string_to_char(type_s);
    free(type_s);
    switch(needed_type){
        case TYPE_DSS:
            if(strcmp(type,"ssh-dss")){
                ssh_set_error(NULL,SSH_FATAL,"Invalid signature type : %s",type);
                buffer_free(tmpbuf);
                free(type);
                return NULL;
            }
            break;
        case TYPE_RSA:
            if(strcmp(type,"ssh-rsa")){
                ssh_set_error(NULL,SSH_FATAL,"Invalid signature type : %s",type);
                buffer_free(tmpbuf);
                free(type);
                return NULL;
            }
            break;
        default:
            ssh_set_error(NULL,SSH_FATAL,"Invalid signature type : %s",type);
            free(type);
            buffer_free(tmpbuf);
            return NULL;
    }
    free(type);
    switch(needed_type){
        case TYPE_DSS:
            rs=buffer_get_ssh_string(tmpbuf);
            buffer_free(tmpbuf);
            if(!rs || string_len(rs)!=40){ /* 40 is the dual signature blob len. */
                if(rs)
                    free(rs);
                return NULL;
            }
            /* we make use of strings (because we have all-made functions to convert them to bignums (ou pas ;)*/
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&sig,NULL,"(sig-val(dsa(r %b)(s %b)))",20,rs->string,20,rs->string+20);
#elif defined HAVE_LIBCRYPTO
            r=string_new(20);
            s=string_new(20);
            string_fill(r,rs->string,20);
            string_fill(s,rs->string+20,20);
            sig=DSA_SIG_new();
            sig->r=make_string_bn(r); /* is that really portable ? Openssh's hack isn't better */
            sig->s=make_string_bn(s);
            free(r);
            free(s);
#endif
#ifdef DEBUG_CRYPTO
            ssh_print_hexa("r",rs->string,20);
            ssh_print_hexa("s",rs->string+20,20);
#endif
            free(rs);
            sign->type=TYPE_DSS;
            sign->dsa_sign=sig;
            return sign;
        case TYPE_RSA:
            e=buffer_get_ssh_string(tmpbuf);
            buffer_free(tmpbuf);
            if(!e){
                return NULL;
            }
            len=string_len(e);
#ifdef HAVE_LIBGCRYPT
            rsalen=(gcry_pk_get_nbits(pubkey->rsa_pub)+7)/8;
#elif defined HAVE_LIBCRYPTO
            rsalen=RSA_size(pubkey->rsa_pub);
#endif
            if(len>rsalen){
                free(e);
                free(sign);
                ssh_set_error(NULL,SSH_FATAL,"signature too big ! %d instead of %d",len,rsalen);
                return NULL;
            }
            if(len<rsalen)
                ssh_say(0,"Len %d < %d\n",len,rsalen);
            sign->type=TYPE_RSA;
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&sig,NULL,"(sig-val(rsa(s %b)))",string_len(e),e->string);
            sign->rsa_sign=sig;
#elif defined HAVE_LIBCRYPTO
            sign->rsa_sign=e;
#endif
#ifdef DEBUG_CRYPTO
            ssh_say(0,"Len : %d\n",len);
            ssh_print_hexa("rsa signature",e->string,len);
#endif
#ifdef HAVE_LIBGCRYPT
            free(e);
#endif
            return sign;
        default:
            return NULL;
    }
}

void signature_free(SIGNATURE *sign){
    if(!sign)
        return;
    switch(sign->type){
        case TYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sign->dsa_sign);
#elif defined HAVE_LIBCRYPTO
            DSA_SIG_free(sign->dsa_sign);
#endif
            break;
        case TYPE_RSA:
        case TYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sign->rsa_sign);
#elif defined HAVE_LIBCRYPTO
            free(sign->rsa_sign);
#endif
            break;
        default:
            ssh_say(1,"freeing a signature with no type !\n");
    }
    free(sign);
}

#ifdef HAVE_LIBCRYPTO
/* maybe the missing function from libcrypto */
/* i think now, maybe it's a bad idea to name it has it should have be named in libcrypto */
static STRING *RSA_do_sign(void *payload,int len,RSA *privkey){
    STRING *sign;
    void *buffer=malloc(RSA_size(privkey));
    unsigned int size;
    int err;
    err=RSA_sign(NID_sha1,payload,len,buffer,&size,privkey);
    if(!err){
        free(buffer);
        return NULL;
    }
    sign=string_new(size);
    string_fill(sign,buffer,size);
    free(buffer);
    return sign;
}
#endif

/* this function signs the session id (known as H) as a string then the content of sigbuf */
STRING *ssh_do_sign(SSH_SESSION *session,BUFFER *sigbuf, PRIVATE_KEY *privatekey){
    SHACTX ctx;
    STRING *session_str=string_new(SHA_DIGEST_LEN);
    unsigned char hash[SHA_DIGEST_LEN+1];
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t gcryhash;
#endif
    SIGNATURE *sign;
    STRING *signature;
    CRYPTO *crypto=session->current_crypto?session->current_crypto:session->next_crypto;
    string_fill(session_str,crypto->session_id,SHA_DIGEST_LEN);
    ctx=sha1_init();
    sha1_update(ctx,session_str,string_len(session_str)+4);
    sha1_update(ctx,buffer_get(sigbuf),buffer_get_len(sigbuf));
    sha1_final(hash+1,ctx);
    hash[0]=0;
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Hash being signed with dsa",hash+1,SHA_DIGEST_LEN);
#endif
    free(session_str);
    sign=malloc(sizeof(SIGNATURE));
    switch(privatekey->type){
        case TYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&gcryhash,NULL,"%b",SHA_DIGEST_LEN+1,hash);
            gcry_pk_sign(&sign->dsa_sign,gcryhash,privatekey->dsa_priv);
#elif defined HAVE_LIBCRYPTO
            sign->dsa_sign=DSA_do_sign(hash+1,SHA_DIGEST_LEN,privatekey->dsa_priv);
#ifdef DEBUG_CRYPTO
            ssh_print_bignum("r",sign->dsa_sign->r);
            ssh_print_bignum("s",sign->dsa_sign->s);
#endif
#endif
            sign->rsa_sign=NULL;
            break;
        case TYPE_RSA:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&gcryhash,NULL,"(data(flags pkcs1)(hash sha1 %b))",SHA_DIGEST_LEN,hash+1);
            gcry_pk_sign(&sign->rsa_sign,gcryhash,privatekey->rsa_priv);
#elif defined HAVE_LIBCRYPTO
            sign->rsa_sign=RSA_do_sign(hash+1,SHA_DIGEST_LEN,privatekey->rsa_priv);
#endif
            sign->dsa_sign=NULL;
            break;
    }
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_release(gcryhash);
#endif
    sign->type=privatekey->type;
    if(!sign->dsa_sign && !sign->rsa_sign){
#ifdef HAVE_LIBGCRYPT
        ssh_set_error(session,SSH_FATAL,"Signing : libcrypt error");
#elif HAVE_LIBCRYPTO
        ssh_set_error(session,SSH_FATAL,"Signing : openssl error");
#endif
        signature_free(sign);
        return NULL;
    }
    signature=signature_to_string(sign);
    signature_free(sign);
    return signature;
}

STRING *ssh_encrypt_rsa1(SSH_SESSION *session, STRING *data, PUBLIC_KEY *key){
    int len=string_len(data);
#ifdef HAVE_LIBGCRYPT
    STRING *ret;
    gcry_sexp_t ret_sexp;
    gcry_sexp_t data_sexp;
    const char *tmp;
    size_t size;
    gcry_sexp_build(&data_sexp,NULL,"(data(flags pkcs1)(value %b))",len,data->string);
    gcry_pk_encrypt(&ret_sexp,data_sexp,key->rsa_pub);
    gcry_sexp_release(data_sexp);
    data_sexp=gcry_sexp_find_token(ret_sexp,"a",0);
    tmp=gcry_sexp_nth_data(data_sexp,1,&size);
    if (*tmp == 0)
    {
      size--;
      tmp++;
    }
    ret=string_new(size);
    string_fill(ret,(char *)tmp,size);
    gcry_sexp_release(ret_sexp);
#elif defined HAVE_LIBCRYPTO
    int flen=RSA_size(key->rsa_pub);
    STRING *ret=string_new(flen);
    RSA_public_encrypt(len,data->string,ret->string,key->rsa_pub,
            RSA_PKCS1_PADDING);
#endif
    return ret;
}


/* this function signs the session id */
STRING *ssh_sign_session_id(SSH_SESSION *session, PRIVATE_KEY *privatekey){
    SHACTX ctx;
    unsigned char hash[SHA_DIGEST_LEN+1];
    SIGNATURE *sign;
    STRING *signature;
    CRYPTO *crypto=session->current_crypto?session->current_crypto:session->next_crypto;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t data_sexp;
#endif
    ctx=sha1_init();
    sha1_update(ctx,crypto->session_id,SHA_DIGEST_LEN);
    sha1_final(hash+1,ctx);
    hash[0]=0;
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Hash being signed with dsa",hash+1,SHA_DIGEST_LEN);
#endif
    sign=malloc(sizeof(SIGNATURE));
    switch(privatekey->type){
        case TYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&data_sexp,NULL,"%b",SHA_DIGEST_LEN+1,hash);
            gcry_pk_sign(&sign->dsa_sign,data_sexp,privatekey->dsa_priv);
#elif defined HAVE_LIBCRYPTO
            sign->dsa_sign=DSA_do_sign(hash+1,SHA_DIGEST_LEN,privatekey->dsa_priv);
#ifdef DEBUG_CRYPTO
            ssh_print_bignum("r",sign->dsa_sign->r);
            ssh_print_bignum("s",sign->dsa_sign->s);
#endif
#endif
            sign->rsa_sign=NULL;
            break;
        case TYPE_RSA:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_build(&data_sexp,NULL,"(data(flags pkcs1)(hash sha1 %b))",SHA_DIGEST_LEN,hash+1);
            gcry_pk_sign(&sign->rsa_sign,data_sexp,privatekey->rsa_priv);
#elif defined HAVE_LIBCRYPTO
            sign->rsa_sign=RSA_do_sign(hash+1,SHA_DIGEST_LEN,privatekey->rsa_priv);
#endif
            sign->dsa_sign=NULL;
            break;
    }
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_release(data_sexp);
#endif
    sign->type=privatekey->type;
    if(!sign->dsa_sign && !sign->rsa_sign){
#ifdef HAVE_LIBGCRYPT
        ssh_set_error(session,SSH_FATAL,"Signing : libgcrypt error");
#elif defined HAVE_LIBCRYPTO
        ssh_set_error(session,SSH_FATAL,"Signing : openssl error");
#endif
        signature_free(sign);
        return NULL;
    }
    signature=signature_to_string(sign);
    signature_free(sign);
    return signature;
}

