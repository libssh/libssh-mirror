/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013 by Aris Adamantiadis <aris@badcode.be>
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

#include "libssh/gssapi.h"
#include "libssh/libssh.h"
#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/callbacks.h"

#include <gssapi.h>

/* to remove */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/** current state of an GSSAPI authentication */
enum ssh_gssapi_state_e {
	SSH_GSSAPI_STATE_NONE, /* no status */
	SSH_GSSAPI_STATE_RCV_TOKEN, /* Expecting a token */
	SSH_GSSAPI_STATE_RCV_MIC, /* Expecting a MIC */
};

struct ssh_gssapi_struct{
	enum ssh_gssapi_state_e state; /* current state */
	struct gss_OID_desc_struct mech; /* mechanism being elected for auth */
	gss_cred_id_t server_creds; /* credentials of server */
	gss_ctx_id_t ctx; /* the authentication context */
	gss_name_t client_name; /* Identity of the client */
	char *user; /* username of client */
	char *canonic_user; /* canonic form of the client's username */
	char *service; /* name of the service */
};


/** @internal
 * @initializes a gssapi context for authentication
 */
static int ssh_gssapi_init(ssh_session session){
	if (session->gssapi != NULL)
		return SSH_OK;
	session->gssapi = malloc(sizeof(struct ssh_gssapi_struct));
	if(!session->gssapi){
		ssh_set_error_oom(session);
		return SSH_ERROR;
	}
	ZERO_STRUCTP(session->gssapi);
	session->gssapi->server_creds = GSS_C_NO_CREDENTIAL;
	session->gssapi->ctx = GSS_C_NO_CONTEXT;
	session->gssapi->state = SSH_GSSAPI_STATE_NONE;
	return SSH_OK;
}

/** @internal
 * @frees a gssapi context
 */
static void ssh_gssapi_free(ssh_session session){
	OM_uint32 min;
	if (session->gssapi == NULL)
		return;
	if (session->gssapi->mech.elements)
		SAFE_FREE(session->gssapi->mech.elements);
	if (session->gssapi->user)
		SAFE_FREE(session->gssapi->user);
	if (session->gssapi->server_creds)
		gss_release_cred(&min,&session->gssapi->server_creds);
	SAFE_FREE(session->gssapi);
}

#ifdef WITH_SERVER

/** @internal
 * @brief sends a SSH_MSG_USERAUTH_GSSAPI_RESPONSE packet
 * @param[in] oid the OID that was selected for authentication
 */
static int ssh_gssapi_send_response(ssh_session session, ssh_string oid){
	if (buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_RESPONSE) < 0 ||
			buffer_add_ssh_string(session->out_buffer,oid) < 0) {
		ssh_set_error_oom(session);
		return SSH_ERROR;
	}

	packet_send(session);
	ssh_log(session, SSH_LOG_PACKET,
			"Sent SSH_MSG_USERAUTH_GSSAPI_RESPONSE");
	return SSH_OK;
}

static void ssh_gssapi_log_error(ssh_session session, int verb, const char *msg, int maj_stat){
	gss_buffer_desc buffer;
	OM_uint32 dummy, message_context;
	gss_display_status(&dummy,maj_stat,GSS_C_GSS_CODE, GSS_C_NO_OID, &message_context, &buffer);
	ssh_log(session, verb, "GSSAPI(%s): %s", msg, (const char *)buffer.value);
}

/** @internal
 * @brief handles an user authentication using GSSAPI
 */
int ssh_gssapi_handle_userauth(ssh_session session, const char *user, uint32_t n_oid, ssh_string *oids){
	char service_name[]="host";
	gss_buffer_desc name_buf;
	gss_name_t server_name; /* local server fqdn */
	OM_uint32 maj_stat, min_stat;
	unsigned int i;
	char *ptr;
	gss_OID_set supported; /* oids supported by server */
	gss_OID_set both_supported; /* oids supported by both client and server */
	gss_OID_set selected; /* oid selected for authentication */
	int present=0;
	int oid_count=0;
	struct gss_OID_desc_struct oid;

	gss_create_empty_oid_set(&min_stat, &both_supported);

	maj_stat = gss_indicate_mechs(&min_stat, &supported);
	for (i=0; i < supported->count; ++i){
		ptr=ssh_get_hexa(supported->elements[i].elements, supported->elements[i].length);
		printf("supported %d : %s\n",i, ptr);
		free(ptr);
	}

	for (i=0 ; i< n_oid ; ++i){
		unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
		size_t len = ssh_string_len(oids[i]);
		if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
			ssh_log(session,SSH_LOG_WARNING,"GSSAPI: received invalid OID");
			continue;
		}
		oid.elements = &oid_s[2];
		oid.length = len - 2;
		gss_test_oid_set_member(&min_stat,&oid,supported,&present);
		if(present){
			gss_add_oid_set_member(&min_stat,&oid,&both_supported);
			oid_count++;
		}
	}
	gss_release_oid_set(&min_stat, &supported);
	if (oid_count == 0){
		ssh_log(session,SSH_LOG_PROTOCOL,"GSSAPI: no OID match");
		ssh_auth_reply_default(session, 0);
		gss_release_oid_set(&min_stat, &both_supported);
		return SSH_OK;
	}
	/* from now we have room for context */
	if (ssh_gssapi_init(session) == SSH_ERROR)
		return SSH_ERROR;

	name_buf.value = service_name;
	name_buf.length = strlen(name_buf.value) + 1;
	maj_stat = gss_import_name(&min_stat, &name_buf,
			(gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &server_name);
	if (maj_stat != GSS_S_COMPLETE) {
		ssh_log(session, 0, "importing name %d, %d", maj_stat, min_stat);
		ssh_gssapi_log_error(session, 0, "importing name", maj_stat);
		return -1;
	}

	maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
			both_supported, GSS_C_ACCEPT,
			&session->gssapi->server_creds, &selected, NULL);
	gss_release_name(&min_stat, &server_name);
	gss_release_oid_set(&min_stat, &both_supported);

	if (maj_stat != GSS_S_COMPLETE) {
		ssh_log(session, 0, "error acquiring credentials %d, %d", maj_stat, min_stat);
		ssh_gssapi_log_error(session, 0, "acquiring creds", maj_stat);
		ssh_auth_reply_default(session,0);
		return SSH_ERROR;
	}

	ssh_log(session, 0, "acquiring credentials %d, %d", maj_stat, min_stat);

	/* finding which OID from client we selected */
	for (i=0 ; i< n_oid ; ++i){
		unsigned char *oid_s = (unsigned char *) ssh_string_data(oids[i]);
		size_t len = ssh_string_len(oids[i]);
		if(len < 2 || oid_s[0] != SSH_OID_TAG || ((size_t)oid_s[1]) != len - 2){
			ssh_log(session,SSH_LOG_WARNING,"GSSAPI: received invalid OID");
			continue;
		}
		oid.elements = &oid_s[2];
		oid.length = len - 2;
		gss_test_oid_set_member(&min_stat,&oid,selected,&present);
		if(present){
			ssh_log(session, SSH_LOG_PACKET, "Selected oid %d", i);
			break;
		}
	}
	session->gssapi->mech.length = oid.length;
	session->gssapi->mech.elements = malloc(oid.length);
	if (session->gssapi->mech.elements == NULL){
		ssh_set_error_oom(session);
		return SSH_ERROR;
	}
	memcpy(session->gssapi->mech.elements, oid.elements, oid.length);
	gss_release_oid_set(&min_stat, &selected);
	session->gssapi->user = strdup(user);
	session->gssapi->service = service_name;
	session->gssapi->state = SSH_GSSAPI_STATE_RCV_TOKEN;
	return ssh_gssapi_send_response(session, oids[i]);
}

static char * ssh_gssapi_name_to_char(ssh_session session, gss_name_t name){
	gss_buffer_desc buffer;
	OM_uint32 maj_stat, min_stat;
	char *ptr;
	maj_stat = gss_display_name(&min_stat, name, &buffer, NULL);
	ssh_gssapi_log_error(session, 0, "converting name", maj_stat);
	ptr=malloc(buffer.length + 1);
	memcpy(ptr, buffer.value, buffer.length);
	ptr[buffer.length] = '\0';
	gss_release_buffer(&min_stat, &buffer);
	return ptr;

}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_token){
	ssh_string token;
	char *hexa;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;
	gss_name_t client_name = GSS_C_NO_NAME;
	OM_uint32 ret_flags=0;
	gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;
	gss_channel_bindings_t input_bindings=GSS_C_NO_CHANNEL_BINDINGS;
	//char *name;
	(void)user;
	(void)type;

	ssh_log(session, SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_TOKEN");
	if (!session->gssapi || session->gssapi->state != SSH_GSSAPI_STATE_RCV_TOKEN){
		ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_TOKEN in invalid state");
		return SSH_PACKET_USED;
	}
	token = buffer_get_ssh_string(packet);

	if (token == NULL){
		ssh_set_error(session, SSH_REQUEST_DENIED, "ssh_packet_userauth_gssapi_token: invalid packet");
		return SSH_PACKET_USED;
	}
	hexa = ssh_get_hexa(ssh_string_data(token),ssh_string_len(token));
	ssh_log(session, SSH_LOG_PACKET, "GSSAPI Token : %s",hexa);
	SAFE_FREE(hexa);
	input_token.length = ssh_string_len(token);
	input_token.value = ssh_string_data(token);

	maj_stat = gss_accept_sec_context(&min_stat, &session->gssapi->ctx, session->gssapi->server_creds,
			&input_token, input_bindings, &client_name, NULL /*mech_oid*/, &output_token, &ret_flags,
			NULL /*time*/, &deleg_cred);
	ssh_gssapi_log_error(session, 0, "accepting token", maj_stat);
	ssh_string_free(token);
	if (client_name != GSS_C_NO_NAME){
		session->gssapi->client_name = client_name;
		session->gssapi->canonic_user = ssh_gssapi_name_to_char(session, client_name);
	}
	if (GSS_ERROR(maj_stat)){
		ssh_log(session, SSH_LOG_PROTOCOL, "Gss api error\n");
		ssh_auth_reply_default(session,0);
		ssh_gssapi_free(session);
		session->gssapi=NULL;
		return SSH_PACKET_USED;
	}

	if (output_token.length != 0){
		hexa = ssh_get_hexa(output_token.value, output_token.length);
		ssh_log(session, SSH_LOG_PACKET, "GSSAPI: sending token %s",hexa);
		SAFE_FREE(hexa);
		token = ssh_string_new(output_token.length);
		ssh_string_fill(token, output_token.value, output_token.length);
		buffer_add_u8(session->out_buffer, SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
		buffer_add_ssh_string(session->out_buffer,token);
		packet_send(session);
		ssh_string_free(token);
	}
	if(maj_stat == GSS_S_COMPLETE){
		session->gssapi->state = SSH_GSSAPI_STATE_RCV_MIC;
	}
	return SSH_PACKET_USED;
}

static ssh_buffer ssh_gssapi_build_mic(ssh_session session){
	ssh_buffer mic_buffer = ssh_buffer_new();
	ssh_string str;
	if(!mic_buffer){
		return NULL;
	}
	str = ssh_string_new(session->current_crypto->digest_len);
	ssh_string_fill(str, session->current_crypto->session_id, session->current_crypto->digest_len);
	buffer_add_ssh_string(mic_buffer, str);
	ssh_string_free(str);

	buffer_add_u8(mic_buffer, SSH2_MSG_USERAUTH_REQUEST);

	str = ssh_string_from_char(session->gssapi->user);
	buffer_add_ssh_string(mic_buffer, str);
	ssh_string_free(str);

	str= ssh_string_from_char("ssh-connection");
	buffer_add_ssh_string(mic_buffer, str);
	ssh_string_free(str);

	str = ssh_string_from_char("gssapi-with-mic");
	buffer_add_ssh_string(mic_buffer, str);
	ssh_string_free(str);

	return mic_buffer;
}

SSH_PACKET_CALLBACK(ssh_packet_userauth_gssapi_mic){
	ssh_string mic_token;
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc mic_buf = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic_token_buf = GSS_C_EMPTY_BUFFER;
	ssh_buffer mic_buffer;

	(void)user;
	(void)type;

	ssh_log(session, SSH_LOG_PACKET,"Received SSH_MSG_USERAUTH_GSSAPI_MIC");
	mic_token = buffer_get_ssh_string(packet);
	if (!mic_token){
		ssh_set_error(session, SSH_FATAL, "Missing MIC in packet");
		goto error;
	}
	if (!session->gssapi || session->gssapi->state != SSH_GSSAPI_STATE_RCV_MIC){
		ssh_set_error(session, SSH_FATAL, "Received SSH_MSG_USERAUTH_GSSAPI_MIC in invalid state");
		goto error;
	}

	mic_buffer = ssh_gssapi_build_mic(session);
	if(!mic_buffer){
		ssh_set_error_oom(session);
		goto error;
	}
	mic_buf.length = ssh_buffer_get_len(mic_buffer);
	mic_buf.value = ssh_buffer_get_begin(mic_buffer);
	mic_token_buf.length = ssh_string_len(mic_token);
	mic_token_buf.value = ssh_string_data(mic_token);

	maj_stat = gss_verify_mic(&min_stat, session->gssapi->ctx, &mic_buf, &mic_token_buf, NULL);
	ssh_gssapi_log_error(session, 0, "verifying MIC", maj_stat);
	ssh_gssapi_log_error(session, 0, "verifying MIC (min stat)", min_stat);
	if (maj_stat == GSS_S_DEFECTIVE_TOKEN)

	if(GSS_ERROR(maj_stat))
		goto error;

	if (ssh_callbacks_exists(session->server_callbacks, auth_gssapi_mic_function)){
		switch(session->server_callbacks->auth_gssapi_mic_function(session,
				session->gssapi->canonic_user, session->server_callbacks->userdata)){
		case SSH_AUTH_SUCCESS:
			ssh_auth_reply_success(session, 0);
			break;
		case SSH_AUTH_PARTIAL:
			ssh_auth_reply_success(session, 1);
			break;
		default:
			ssh_auth_reply_default(session, 0);
			break;
		}
	}

	ssh_gssapi_free(session);
	return SSH_PACKET_USED;

	error:
	ssh_auth_reply_default(session,0);
	ssh_gssapi_free(session);
	return SSH_PACKET_USED;
}

#endif
