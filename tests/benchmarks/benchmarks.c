/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#include "config.h"
#include "benchmarks.h"
#include <libssh/libssh.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const char *libssh_benchmarks_names[]={
    "null",
    "benchmark_raw_upload"
};

#ifdef HAVE_ARGP_H
#include <argp.h>

const char *argp_program_version = "libssh benchmarks 2010-12-28";
const char *argp_program_bug_address = "Aris Adamantiadis <aris@0xbadc0de.be>";

static char **cmdline;

/* Program documentation. */
static char doc[] = "libssh benchmarks";


/* The options we understand. */
static struct argp_option options[] = {
  {
    .name  = "verbose",
    .key   = 'v',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Make libssh benchmark more verbose",
    .group = 0
  },
  {
    .name  = "raw-upload",
    .key   = '1',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Upload raw data using channel",
    .group = 0
  },
  {
    .name  = "host",
    .key   = 'h',
    .arg   = "HOST",
    .flags = 0,
    .doc   = "Add a host to connect for benchmark (format user@hostname)",
    .group = 0
  },
  {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
   * know is a pointer to our arguments structure.
   */
  struct argument_s *arguments = state->input;

  /* arg is currently not used */
  (void) arg;

  switch (key) {
    case '1':
      arguments->benchmarks[key - '1' + 1] = 1;
      arguments->ntests ++;
      break;
    case 'v':
      arguments->verbose++;
      break;
    case 'h':
      if(arguments->nhosts >= MAX_HOSTS_CONNECT){
        fprintf(stderr, "Too much hosts\n");
        return ARGP_ERR_UNKNOWN;
      }
      arguments->hosts[arguments->nhosts]=arg;
      arguments->nhosts++;
      break;
    case ARGP_KEY_ARG:
      /* End processing here. */
      cmdline = &state->argv [state->next - 1];
      state->next = state->argc;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};

#endif /* HAVE_ARGP_H */

static void cmdline_parse(int argc, char **argv, struct argument_s *arguments) {
  /*
   * Parse our arguments; every option seen by parse_opt will
   * be reflected in arguments.
   */
#ifdef HAVE_ARGP_H
  argp_parse(&argp, argc, argv, 0, 0, arguments);
#else /* HAVE_ARGP_H */
  (void) argc;
  (void) argv;
  (void) arguments;
#endif /* HAVE_ARGP_H */
}

static void arguments_init(struct argument_s *arguments){
  memset(arguments,0,sizeof(*arguments));
}

static ssh_session connect_host(const char *host, int verbose){
  ssh_session session=ssh_new();
  if(session==NULL)
    goto error;
  if(ssh_options_set(session,SSH_OPTIONS_HOST, host)<0)
    goto error;
  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbose);
  if(ssh_connect(session)==SSH_ERROR)
    goto error;
  if(ssh_userauth_autopubkey(session,NULL) != SSH_AUTH_SUCCESS)
    goto error;
  return session;
error:
  fprintf(stderr,"Error connecting to \"%s\": %s\n",host,ssh_get_error(session));
  ssh_free(session);
  return NULL;
}

static char *network_speed(float bps){
  static char buffer[128];
  if(bps > 1000*1000*1000){
    /* Gbps */
    snprintf(buffer,sizeof(buffer),"%f Gbps",bps/(1000*1000*1000));
  } else if(bps > 1000*1000){
    /* Mbps */
    snprintf(buffer,sizeof(buffer),"%f Mbps",bps/(1000*1000));
  } else if(bps > 1000){
    snprintf(buffer,sizeof(buffer),"%f Kbps",bps/1000);
  } else {
    snprintf(buffer,sizeof(buffer),"%f bps",bps);
  }
  return buffer;
}

static void do_benchmarks(ssh_session session, struct argument_s *arguments,
    const char *hostname){
  float ping_rtt=0.0;
  float ssh_rtt=0.0;
  float bps=0.0;
  int err;

  if(arguments->verbose>0)
    fprintf(stdout,"Testing ICMP RTT\n");
  err=benchmarks_ping_latency(hostname, &ping_rtt);
  if(err == 0){
    fprintf(stdout,"ping RTT : %f ms\n",ping_rtt);
  }
  err=benchmarks_ssh_latency(session, &ssh_rtt);
  if(err==0){
    fprintf(stdout, "SSH RTT : %f ms\n",ssh_rtt);
  }
  if(arguments->benchmarks[BENCHMARK_RAW_UPLOAD-1]){
    err=benchmarks_raw_up(session,arguments,&bps);
    if(err==0){
      fprintf(stdout, "%s : %s : %s\n",hostname,
          libssh_benchmarks_names[BENCHMARK_RAW_UPLOAD], network_speed(bps));
    }
  }
}

int main(int argc, char **argv){
  struct argument_s arguments;
  ssh_session session;
  int i;

  arguments_init(&arguments);
  cmdline_parse(argc, argv, &arguments);
  if (arguments.nhosts==0){
    fprintf(stderr,"At least one host (-h) must be specified\n");
    return EXIT_FAILURE;
  }
  if (arguments.ntests==0){
    for(i=1; i < BENCHMARK_NUMBER ; ++i){
      arguments.benchmarks[i-1]=1;
    }
    arguments.ntests=BENCHMARK_NUMBER-1;
  }
  if (arguments.verbose > 0){
    fprintf(stdout, "Will try hosts ");
    for(i=0;i<arguments.nhosts;++i){
      fprintf(stdout,"\"%s\" ", arguments.hosts[i]);
    }
    fprintf(stdout,"with benchmarks ");
    for(i=0;i<BENCHMARK_NUMBER-1;++i){
      if(arguments.benchmarks[i])
        fprintf(stdout,"\"%s\" ",libssh_benchmarks_names[i+1]);
    }
    fprintf(stdout,"\n");
  }

  for(i=0; i<arguments.nhosts;++i){
    if(arguments.verbose > 0)
      fprintf(stdout,"Connecting to \"%s\"...\n",arguments.hosts[i]);
    session=connect_host(arguments.hosts[i], arguments.verbose);
    if(session != NULL && arguments.verbose > 0)
      fprintf(stdout,"Success\n");
    if(session == NULL){
      fprintf(stderr,"Errors occured, stopping\n");
      return EXIT_FAILURE;
    }
    do_benchmarks(session, &arguments, arguments.hosts[i]);
    ssh_disconnect(session);
    ssh_free(session);
  }
  return EXIT_SUCCESS;
}

