/* kex.c is used well, in key exchange :-) */
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/ssh1.h"

#ifdef HAVE_LIBGCRYPT
#define BLOWFISH "blowfish-cbc,"
#define AES "aes256-cbc,aes192-cbc,aes128-cbc,"
#define DES "3des-cbc"
#elif defined HAVE_LIBCRYPTO
#ifdef HAVE_OPENSSL_BLOWFISH_H
#define BLOWFISH "blowfish-cbc,"
#else
#define BLOWFISH ""
#endif
#ifdef HAVE_OPENSSL_AES_H
#define AES "aes256-cbc,aes192-cbc,aes128-cbc,"
#else
#define AES ""
#endif
#define DES "3des-cbc"
#endif

#ifdef HAVE_LIBZ
#define ZLIB "none,zlib"
#else
#define ZLIB "none"
#endif

char *default_methods[]={
	"diffie-hellman-group1-sha1","ssh-dss,ssh-rsa",AES BLOWFISH DES,AES BLOWFISH
        DES, "hmac-sha1","hmac-sha1","none","none","","",NULL };
char *supported_methods[]={
    "diffie-hellman-group1-sha1","ssh-dss,ssh-rsa",AES BLOWFISH DES,AES BLOWFISH
        DES, "hmac-sha1","hmac-sha1",ZLIB,ZLIB,"","",NULL };
/* descriptions of the key exchange packet */
char *ssh_kex_nums[]={
	"kex algos","server host key algo","encryption client->server","encryption server->client",
	"mac algo client->server","mac algo server->client","compression algo client->server",
	"compression algo server->client","languages client->server","languages server->client",NULL};

/* tokenize will return a token of strings delimited by ",". the first element has to be freed */
static char **tokenize(char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *ptr=chain=strdup(chain);
    while(*ptr){
        if(*ptr==','){
            n++;
            *ptr=0;
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens=malloc(sizeof(char *) * (n+1) ); /* +1 for the null */
    ptr=chain;
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        while(*ptr)
            ptr++; // find a zero
        ptr++; // then go one step further
    }
    tokens[i]=NULL;
    return tokens;
}

/* same as tokenize(), but with spaces instead of ',' */
char **space_tokenize(char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *ptr=chain=strdup(chain);
    while(*ptr==' ')
        ++ptr; /* skip initial spaces */
    while(*ptr){
        if(*ptr==' '){
            n++; /* count one token per word */
            *ptr=0;
            while(*(ptr+1)==' '){ /* don't count if the tokens have more than 2 spaces */
                *(ptr++)=0;
            }
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens=malloc(sizeof(char *) * (n+1) ); /* +1 for the null */
    ptr=chain; /* we don't pass the initial spaces because the "chain" pointer is needed by the caller */
                    /* function to free the tokens. */
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        if(i!=n-1){
            while(*ptr)
                ptr++; // find a zero
            while(!*(ptr+1))
                ++ptr; /* if the zero is followed by other zeros, go through them */
            ptr++; // then go one step further
        }
    }
    tokens[i]=NULL;
    return tokens;
}

/* find_matching gets 2 parameters : a list of available objects (in_d), separated by colons,*/
/* and a list of prefered objects (what_d) */
/* it will return a strduped pointer on the first prefered object found in the available objects list */

char *ssh_find_matching(char *in_d, char *what_d){
    char ** tok_in, **tok_what;
    int i_in, i_what;
    char *ret;
    
    if( ! (in_d && what_d))
        return NULL; /* don't deal with null args */
    ssh_say(3,"find_matching(\"%s\",\"%s\") = ",in_d,what_d);
    tok_in=tokenize(in_d);
    tok_what=tokenize(what_d);
    for(i_in=0; tok_in[i_in]; ++i_in){
        for(i_what=0; tok_what[i_what] ; ++i_what){
            if(!strcmp(tok_in[i_in],tok_what[i_what])){
                /* match */            
                ssh_say(3,"\"%s\"\n",tok_in[i_in]);
                ret=strdup(tok_in[i_in]);
                /* free the tokens */
                free(tok_in[0]);
                free(tok_what[0]);
                free(tok_in);
                free(tok_what);
                return ret;
            }
        }
    }
    ssh_say(3,"NULL\n");
    free(tok_in[0]);
    free(tok_what[0]);
    free(tok_in);
    free(tok_what);
    return NULL;
}

int ssh_get_kex(SSH_SESSION *session,int server_kex ){
    STRING *str;
    char *strings[10];
    int i;
    if(packet_wait(session,SSH2_MSG_KEXINIT,1))
        return -1;
    if(buffer_get_data(session->in_buffer,session->server_kex.cookie,16)!=16){
        ssh_set_error(session,SSH_FATAL,"get_kex(): no cookie in packet");
        return -1;
    }
    hashbufin_add_cookie(session,session->server_kex.cookie);
    memset(strings,0,sizeof(char *)*10);
    for(i=0;i<10;++i){
        str=buffer_get_ssh_string(session->in_buffer);
        if(!str)
            break;
        if(str){
            buffer_add_ssh_string(session->in_hashbuf,str);
            strings[i]=string_to_char(str);
            free(str);
        } else
            strings[i]=NULL;
    }
    /* copy the server kex info into an array of strings */
    if(server_kex){
        session->client_kex.methods=malloc( 10 * sizeof(char **));
        for(i=0;i<10;++i)
            session->client_kex.methods[i]=strings[i];
    } else { // client     
        session->server_kex.methods=malloc( 10 * sizeof(char **));
        for(i=0;i<10;++i)
            session->server_kex.methods[i]=strings[i];
    }
    return 0;
}

void ssh_list_kex(KEX *kex){
    int i=0;
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("session cookie",kex->cookie,16);
#endif
    for(i=0;i<10;i++){
        ssh_say(2,"%s : %s\n",ssh_kex_nums[i],kex->methods[i]);
    }
}

/* set_kex basicaly look at the option structure of the session and set the output kex message */
/* it must be aware of the server kex message */
/* it can fail if option is null, not any user specified kex method matches the server one, if not any default kex matches */

int set_kex(SSH_SESSION *session){
    KEX *server = &session->server_kex;
    KEX *client=&session->client_kex;
    SSH_OPTIONS *options=session->options;
    int i;
    char *wanted;
    /* the client might ask for a specific cookie to be sent. useful for server debugging */
    if(options->wanted_cookie)
        memcpy(client->cookie,options->wanted_cookie,16);
    else
        ssh_get_random(client->cookie,16,0);
    client->methods=malloc(10 * sizeof(char **));
    memset(client->methods,0,10*sizeof(char **));
    for (i=0;i<10;i++){
        if(!(wanted=options->wanted_methods[i]))
            wanted=default_methods[i];
        client->methods[i]=ssh_find_matching(server->methods[i],wanted);
        if(!client->methods[i] && i < SSH_LANG_C_S){
            ssh_set_error(session,SSH_FATAL,"kex error : did not find one of algos %s in list %s for %s",
            wanted,server->methods[i],ssh_kex_nums[i]);
            return -1;
        } else {
            if(i>=SSH_LANG_C_S && !client->methods[i])
                client->methods[i]=strdup(""); // we can safely do that for languages
        }
    }
    return 0;
}

/* this function only sends the predefined set of kex methods */    
void ssh_send_kex(SSH_SESSION *session, int server_kex){
    STRING *str;
    int i=0;
    KEX *kex=(server_kex ? &session->server_kex : &session->client_kex);
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH2_MSG_KEXINIT);
    buffer_add_data(session->out_buffer,kex->cookie,16);
    hashbufout_add_cookie(session);
    ssh_list_kex(kex);
    for(i=0;i<10;i++){
        str=string_from_char(kex->methods[i]);
        buffer_add_ssh_string(session->out_hashbuf,str);
        buffer_add_ssh_string(session->out_buffer,str);
        free(str);
    }
    i=0;
    buffer_add_u8(session->out_buffer,0);
    buffer_add_u32(session->out_buffer,0);
    packet_send(session);
}

/* returns 1 if at least one of the name algos is in the default algorithms table */
int verify_existing_algo(int algo, char *name){
    char *ptr;
    if(algo>9 || algo <0)
        return -1;
    ptr=ssh_find_matching(supported_methods[algo],name);
    if(ptr){
        free(ptr);
        return 1;
    }
    return 0;
}

/* makes a STRING contating 3 strings : ssh-rsa1,e and n */
/* this is a public key in openssh's format */
static STRING *make_rsa1_string(STRING *e, STRING *n){
    BUFFER *buffer=buffer_new();
    STRING *rsa=string_from_char("ssh-rsa1");
    STRING *ret;
    buffer_add_ssh_string(buffer,rsa);
    free(rsa);
    buffer_add_ssh_string(buffer,e);
    buffer_add_ssh_string(buffer,n);
    ret=string_new(buffer_get_len(buffer));
    string_fill(ret,buffer_get(buffer),buffer_get_len(buffer));
    buffer_free(buffer);
    return ret;
}

static void build_session_id1(SSH_SESSION *session, STRING *servern, 
        STRING *hostn){
    MD5CTX md5=md5_init();
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("host modulus",hostn->string,string_len(hostn));
    ssh_print_hexa("server modulus",servern->string,string_len(servern));
#endif
    md5_update(md5,hostn->string,string_len(hostn));
    md5_update(md5,servern->string,string_len(servern));
    md5_update(md5,session->server_kex.cookie,8);
    md5_final(session->next_crypto->session_id,md5);
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("session_id",session->next_crypto->session_id,MD5_DIGEST_LEN);
#endif
}

/* returns 1 if the modulus of k1 is < than the one of k2 */
static int modulus_smaller(PUBLIC_KEY *k1, PUBLIC_KEY *k2){
    bignum n1;
    bignum n2;
    int res;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t sexp;
    sexp=gcry_sexp_find_token(k1->rsa_pub,"n",0);
    n1=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(k2->rsa_pub,"n",0);
    n2=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
#elif defined HAVE_LIBCRYPTO
    n1=k1->rsa_pub->n;
    n2=k2->rsa_pub->n;
#endif
    if(bignum_cmp(n1,n2)<0)
        res=1;
    else
        res=0;
#ifdef HAVE_LIBGCRYPT
    bignum_free(n1);
    bignum_free(n2);
#endif
    return res;
    
}

#define ABS(A) ( (A)<0 ? -(A):(A) )
STRING *encrypt_session_key(SSH_SESSION *session, PUBLIC_KEY *svrkey,
        PUBLIC_KEY *hostkey,int slen, int hlen ){
    unsigned char buffer[32];
    int i;
    STRING *data1,*data2;
    /* first, generate a session key */
    
    ssh_get_random(session->next_crypto->encryptkey,32,1);
    memcpy(buffer,session->next_crypto->encryptkey,32);
    memcpy(session->next_crypto->decryptkey,
            session->next_crypto->encryptkey,32);
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("session key",buffer,32);
#endif
    /* xor session key with session_id */
    for (i=0;i<16;++i)
        buffer[i]^=session->next_crypto->session_id[i];
    data1=string_new(32);
    string_fill(data1,buffer,32);
    if(ABS(hlen-slen)<128){
        ssh_say(1,"Difference between server modulus and host modulus is only %d. It's illegal and may not work\n",
                ABS(hlen-slen));
    }
    if(modulus_smaller(svrkey,hostkey)){
        data2=ssh_encrypt_rsa1(session,data1,svrkey);
        free(data1);
        data1=ssh_encrypt_rsa1(session,data2,hostkey);
    } else {
        data2=ssh_encrypt_rsa1(session,data1,hostkey);
        free(data1);
        data1=ssh_encrypt_rsa1(session,data2,svrkey);
    }
    return data1;
}


/* SSH-1 functions */
/*    2 SSH_SMSG_PUBLIC_KEY
 *
 *    8 bytes      anti_spoofing_cookie
 *    32-bit int   server_key_bits
 *    mp-int       server_key_public_exponent
 *    mp-int       server_key_public_modulus
 *    32-bit int   host_key_bits
 *    mp-int       host_key_public_exponent
 *    mp-int       host_key_public_modulus
 *    32-bit int   protocol_flags
 *    32-bit int   supported_ciphers_mask
 *    32-bit int   supported_authentications_mask
 */

int ssh_get_kex1(SSH_SESSION *session){
    u32 server_bits, host_bits, protocol_flags, 
        supported_ciphers_mask, supported_authentications_mask;
    STRING *server_exp=NULL;
    STRING *server_mod=NULL;
    STRING *host_exp=NULL;
    STRING *host_mod=NULL;
    STRING *serverkey;
    STRING *hostkey;
    STRING *enc_session;
    PUBLIC_KEY *svr,*host;
    int ko;
    u16 bits;
    ssh_say(3,"Waiting for a SSH_SMSG_PUBLIC_KEY\n");
    if(packet_wait(session,SSH_SMSG_PUBLIC_KEY,1)){
        return -1;
    }
    ssh_say(3,"Got a SSH_SMSG_PUBLIC_KEY\n");
    if(buffer_get_data(session->in_buffer,session->server_kex.cookie,8)!=8){
        ssh_set_error(NULL,SSH_FATAL,"Can't get cookie in buffer");
        return -1;
    }
    buffer_get_u32(session->in_buffer,&server_bits);
    server_exp=buffer_get_mpint(session->in_buffer);
    server_mod=buffer_get_mpint(session->in_buffer);
    buffer_get_u32(session->in_buffer,&host_bits);
    host_exp=buffer_get_mpint(session->in_buffer);
    host_mod=buffer_get_mpint(session->in_buffer);
    buffer_get_u32(session->in_buffer,&protocol_flags);
    buffer_get_u32(session->in_buffer,&supported_ciphers_mask);
    ko=buffer_get_u32(session->in_buffer,&supported_authentications_mask);
    if((ko!=sizeof(u32)) || !host_mod || !host_exp || !server_mod || !server_exp){
        ssh_say(2,"Invalid SSH_SMSG_PUBLIC_KEY packet\n");
        ssh_set_error(NULL,SSH_FATAL,"Invalid SSH_SMSG_PUBLIC_KEY packet");
        if(host_mod)
            free(host_mod);
        if(host_exp)
            free(host_exp);
        if(server_mod)
            free(server_mod);
        if(server_exp)
            free(server_exp);
        return -1;
    }
    server_bits=ntohl(server_bits);
    host_bits=ntohl(host_bits);
    protocol_flags=ntohl(protocol_flags);
    supported_ciphers_mask=ntohl(supported_ciphers_mask);
    supported_authentications_mask=ntohl(supported_authentications_mask);
    ssh_say(1,"server bits: %d ; host bits: %d\nProtocol flags : %.8lx ; "
            "cipher mask : %.8lx ; auth mask: %.8lx\n",server_bits,
            host_bits,protocol_flags,supported_ciphers_mask,
            supported_authentications_mask);
    serverkey=make_rsa1_string(server_exp,server_mod);
    hostkey=make_rsa1_string(host_exp,host_mod);
    build_session_id1(session,server_mod,host_mod);
    free(server_exp);
    free(server_mod);
    free(host_exp);
    free(host_mod);
    svr=publickey_from_string(serverkey);
    host=publickey_from_string(hostkey);
    session->next_crypto->server_pubkey=string_copy(hostkey);
    session->next_crypto->server_pubkey_type="ssh-rsa1";

    /* now, we must choose an encryption algo */
    /* hardcode 3des */
    if(!(supported_ciphers_mask & (1<<SSH_CIPHER_3DES))){
        ssh_set_error(NULL,SSH_FATAL,"Remote server doesn't accept 3des");
        return -1;
    }
    packet_clear_out(session);
    buffer_add_u8(session->out_buffer,SSH_CMSG_SESSION_KEY);
    buffer_add_u8(session->out_buffer,SSH_CIPHER_3DES);
    buffer_add_data(session->out_buffer,session->server_kex.cookie,8);
    
    enc_session=encrypt_session_key(session,svr,host,server_bits, host_bits);
    bits=string_len(enc_session)*8 - 7;
    ssh_say(2,"%d bits,%d bytes encrypted session\n",bits,string_len(enc_session));
    bits=htons(bits);
    /* the encrypted mpint */
    buffer_add_data(session->out_buffer,&bits,sizeof(u16));
    buffer_add_data(session->out_buffer,enc_session->string,
            string_len(enc_session));
    /* the protocol flags */
    buffer_add_u32(session->out_buffer,0);

    packet_send(session); 
    /* we can set encryption */
    if(crypt_set_algorithms(session))
        return -1;
    session->current_crypto=session->next_crypto;
    session->next_crypto=NULL;
    if(packet_wait(session,SSH_SMSG_SUCCESS,1)){
        char buffer[1024];
        snprintf(buffer,sizeof(buffer),"Key exchange failed : %s",ssh_get_error(session));
        ssh_set_error(session,SSH_FATAL,"%s",buffer);
        return -1;
    }
    ssh_say(1,"received SSH_SMSG_SUCCESS\n");
    return 0;
    
}

