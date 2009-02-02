#ifndef __AGENT_H
#define __AGENT_H

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

#endif /* __AGENT_H */
