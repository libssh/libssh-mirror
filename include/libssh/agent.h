/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 Andreas Schneider <asn@cryptomilk.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __AGENT_H
#define __AGENT_H

#include "libssh/libssh.h"

/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES        1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER          2
#define SSH_AGENTC_RSA_CHALLENGE                 3
#define SSH_AGENT_RSA_RESPONSE                   4
#define SSH_AGENT_FAILURE                        5
#define SSH_AGENT_SUCCESS                        6
#define SSH_AGENTC_ADD_RSA_IDENTITY              7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY           8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES     9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES           11
#define SSH2_AGENT_IDENTITIES_ANSWER             12
#define SSH2_AGENTC_SIGN_REQUEST                 13
#define SSH2_AGENT_SIGN_RESPONSE                 14
#define SSH2_AGENTC_ADD_IDENTITY                 17
#define SSH2_AGENTC_REMOVE_IDENTITY              18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES        19

/* smartcard */
#define SSH_AGENTC_ADD_SMARTCARD_KEY             20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY          21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK                          22
#define SSH_AGENTC_UNLOCK                        23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED        24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED           25
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

#define SSH_AGENT_CONSTRAIN_LIFETIME             1
#define SSH_AGENT_CONSTRAIN_CONFIRM              2

/* extended failure messages */
#define SSH2_AGENT_FAILURE                       30

/* additional error code for ssh.com's ssh-agent2 */
#define SSH_COM_AGENT2_FAILURE                   102

#define SSH_AGENT_OLD_SIGNATURE                  0x01
/* Signature flags from draft-miller-ssh-agent-02 */
#define SSH_AGENT_RSA_SHA2_256                   0x02
#define SSH_AGENT_RSA_SHA2_512                   0x04

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief SSH agent connection context.
 *
 * This structure represents a connection to an SSH authentication agent.
 * It is used by libssh to communicate with the agent for operations such
 * as listing available identities and signing data during authentication.
 */
struct ssh_agent_struct {
  struct ssh_socket_struct *sock;
  ssh_buffer ident;
  unsigned int count;
  ssh_channel channel;
#ifdef _WIN32
  void *pipe_handle;
#endif
};

/* agent.c */

/**
 * @brief Create a new ssh agent structure.
 *
 * Creates and initializes an SSH agent context bound to the given
 * SSH session. The agent connection relies on the session configuration
 * (e.g. agent forwarding).
 *
 * @param session The SSH session the agent will be associated with.
 *
 * @return An allocated ssh agent structure on success, or NULL on error.
 *
 * @note This function does not start or manage an external agent
 *       process; it only connects to an already running agent.
 */
struct ssh_agent_struct *ssh_agent_new(struct ssh_session_struct *session);


void ssh_agent_close(struct ssh_agent_struct *agent);

/**
 * @brief Free an allocated ssh agent structure.
 *
 * @param agent The ssh agent structure to free.
 */
void ssh_agent_free(struct ssh_agent_struct *agent);

/**
 * @brief Check if the ssh agent is running.
 *
 * @param session The SSH session to check for agent availability.
 *
 * @return 1 if an agent is available, 0 otherwise.
 */
int ssh_agent_is_running(struct ssh_session_struct *session);

uint32_t ssh_agent_get_ident_count(struct ssh_session_struct *session);

/**
 * @brief Retrieve the first identity provided by the SSH agent.
 *
 * @param session The SSH session associated with the agent.
 * @param comment Optional pointer to receive the key comment.
 *
 * @return A public key on success, or NULL if no identities are available.
 *
 * @note The returned key is owned by the caller and must be freed
 *       using ssh_key_free().
 */
ssh_key ssh_agent_get_first_ident(struct ssh_session_struct *session,
                                  char **comment);

/**
 * @brief Retrieve the next identity provided by the SSH agent.
 *
 * @param session The SSH session associated with the agent.
 * @param comment Optional pointer to receive the key comment.
 *
 * @return A public key on success, or NULL if no further identities exist.
 *
 * @note The returned key is owned by the caller and must be freed
 *       using ssh_key_free().
 */
ssh_key ssh_agent_get_next_ident(struct ssh_session_struct *session,
                                 char **comment);


/**
 * @brief Request the SSH agent to sign data using a public key.
 *
 * Asks the SSH agent to generate a signature over the provided data
 * using the specified public key.
 *
 * @param session The SSH session associated with the agent.
 * @param pubkey  The public key identifying the signing identity.
 * @param data    The data to be signed.
 *
 * @return A newly allocated ssh_string containing the signature on
 *         success, or NULL on failure.
 *
 * @note This operation requires that the agent possesses the
 *       corresponding private key and may prompt the user for
 *       confirmation depending on agent configuration.
 */
ssh_string ssh_agent_sign_data(ssh_session session,
                               const ssh_key pubkey,
                               struct ssh_buffer_struct *data);
/**
 * @brief Remove an identity from the SSH agent.
 *
 * @param session   The SSH session.
 * @param key       The public key to remove.
 *
 * @return `SSH_OK` on success, `SSH_ERROR` on failure.
 */
int ssh_agent_remove_identity(ssh_session session,
                              const ssh_key key);



#ifdef __cplusplus
}
#endif

#endif /* __AGENT_H */
