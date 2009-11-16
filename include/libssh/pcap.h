#ifndef PCAP_H_
#define PCAP_H_

#include "config.h"
#include "libssh/libssh.h"

#ifdef WITH_PCAP
typedef struct ssh_pcap_context_struct* ssh_pcap_context;
typedef struct ssh_pcap_file_struct* ssh_pcap_file;

ssh_pcap_file ssh_pcap_file_new(void);
int ssh_pcap_file_open(ssh_pcap_file pcap, const char *filename);
int ssh_pcap_file_close(ssh_pcap_file pcap);
void ssh_pcap_file_free(ssh_pcap_file pcap);

/* to be removed from here after tests */
int ssh_pcap_file_write_packet(ssh_pcap_file pcap, ssh_buffer packet, u_int32_t original_len);

ssh_pcap_context ssh_pcap_context_new(ssh_session session);

enum ssh_pcap_direction{
	SSH_PCAP_DIR_IN,
	SSH_PCAP_DIR_OUT
};
void ssh_pcap_context_set_file(ssh_pcap_context, ssh_pcap_file);
int ssh_pcap_context_write(ssh_pcap_context,enum ssh_pcap_direction direction, void *data,
		u_int32_t len, u_int32_t origlen);

void ssh_set_pcap_context(ssh_session session, ssh_pcap_context pcap);

#endif /* WITH_PCAP */
#endif /* PCAP_H_ */
/* vim: set ts=2 sw=2 et cindent: */
