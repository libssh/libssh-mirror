/*
 * config.c - parse the ssh config file
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009-2013    by Andreas Schneider <asn@cryptomilk.org>
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_GLOB_H
# include <glob.h>
#endif
#include <stdbool.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/options.h"

#define MAX_LINE_SIZE 1024

enum ssh_config_opcode_e {
  /* Unknown opcode */
  SOC_UNKNOWN = -3,
  /* Known and not applicable to libssh */
  SOC_NA = -2,
  /* Known but not supported by current libssh version */
  SOC_UNSUPPORTED = -1,
  SOC_HOST,
  SOC_MATCH,
  SOC_HOSTNAME,
  SOC_PORT,
  SOC_USERNAME,
  SOC_IDENTITY,
  SOC_CIPHERS,
  SOC_MACS,
  SOC_COMPRESSION,
  SOC_TIMEOUT,
  SOC_PROTOCOL,
  SOC_STRICTHOSTKEYCHECK,
  SOC_KNOWNHOSTS,
  SOC_PROXYCOMMAND,
  SOC_GSSAPISERVERIDENTITY,
  SOC_GSSAPICLIENTIDENTITY,
  SOC_GSSAPIDELEGATECREDENTIALS,
  SOC_INCLUDE,
  SOC_BINDADDRESS,
  SOC_GLOBALKNOWNHOSTSFILE,
  SOC_LOGLEVEL,
  SOC_HOSTKEYALGORITHMS,
  SOC_KEXALGORITHMS,
  SOC_GSSAPIAUTHENTICATION,
  SOC_KBDINTERACTIVEAUTHENTICATION,
  SOC_PASSWORDAUTHENTICATION,
  SOC_PUBKEYAUTHENTICATION,
  SOC_PUBKEYACCEPTEDTYPES,

  SOC_END /* Keep this one last in the list */
};

struct ssh_config_keyword_table_s {
  const char *name;
  enum ssh_config_opcode_e opcode;
};

static struct ssh_config_keyword_table_s ssh_config_keyword_table[] = {
  { "host", SOC_HOST },
  { "match", SOC_MATCH },
  { "hostname", SOC_HOSTNAME },
  { "port", SOC_PORT },
  { "user", SOC_USERNAME },
  { "identityfile", SOC_IDENTITY },
  { "ciphers", SOC_CIPHERS },
  { "macs", SOC_MACS },
  { "compression", SOC_COMPRESSION },
  { "connecttimeout", SOC_TIMEOUT },
  { "protocol", SOC_PROTOCOL },
  { "stricthostkeychecking", SOC_STRICTHOSTKEYCHECK },
  { "userknownhostsfile", SOC_KNOWNHOSTS },
  { "proxycommand", SOC_PROXYCOMMAND },
  { "gssapiserveridentity", SOC_GSSAPISERVERIDENTITY },
  { "gssapiclientidentity", SOC_GSSAPICLIENTIDENTITY },
  { "gssapidelegatecredentials", SOC_GSSAPIDELEGATECREDENTIALS },
  { "include", SOC_INCLUDE },
  { "bindaddress", SOC_BINDADDRESS},
  { "globalknownhostsfile", SOC_GLOBALKNOWNHOSTSFILE},
  { "loglevel", SOC_LOGLEVEL},
  { "hostkeyalgorithms", SOC_HOSTKEYALGORITHMS},
  { "kexalgorithms", SOC_KEXALGORITHMS},
  { "mac", SOC_UNSUPPORTED}, /* SSHv1 */
  { "gssapiauthentication", SOC_GSSAPIAUTHENTICATION},
  { "kbdinteractiveauthentication", SOC_KBDINTERACTIVEAUTHENTICATION},
  { "passwordauthentication", SOC_PASSWORDAUTHENTICATION},
  { "pubkeyauthentication", SOC_PUBKEYAUTHENTICATION},
  { "addkeystoagent", SOC_UNSUPPORTED},
  { "addressfamily", SOC_UNSUPPORTED},
  { "batchmode", SOC_UNSUPPORTED},
  { "canonicaldomains", SOC_UNSUPPORTED},
  { "canonicalizefallbacklocal", SOC_UNSUPPORTED},
  { "canonicalizehostname", SOC_UNSUPPORTED},
  { "canonicalizemaxdots", SOC_UNSUPPORTED},
  { "canonicalizepermittedcnames", SOC_UNSUPPORTED},
  { "certificatefile", SOC_UNSUPPORTED},
  { "challengeresponseauthentication", SOC_UNSUPPORTED},
  { "checkhostip", SOC_UNSUPPORTED},
  { "cipher", SOC_UNSUPPORTED}, /* SSHv1 */
  { "compressionlevel", SOC_UNSUPPORTED}, /* SSHv1 */
  { "connectionattempts", SOC_UNSUPPORTED},
  { "enablesshkeysign", SOC_UNSUPPORTED},
  { "fingerprinthash", SOC_UNSUPPORTED},
  { "forwardagent", SOC_UNSUPPORTED},
  { "gssapikeyexchange", SOC_UNSUPPORTED},
  { "gssapirenewalforcesrekey", SOC_UNSUPPORTED},
  { "gssapitrustdns", SOC_UNSUPPORTED},
  { "hashknownhosts", SOC_UNSUPPORTED},
  { "hostbasedauthentication", SOC_UNSUPPORTED},
  { "hostbasedkeytypes", SOC_UNSUPPORTED},
  { "hostkeyalias", SOC_UNSUPPORTED},
  { "identitiesonly", SOC_UNSUPPORTED},
  { "identityagent", SOC_UNSUPPORTED},
  { "ipqos", SOC_UNSUPPORTED},
  { "kbdinteractivedevices", SOC_UNSUPPORTED},
  { "nohostauthenticationforlocalhost", SOC_UNSUPPORTED},
  { "numberofpasswordprompts", SOC_UNSUPPORTED},
  { "pkcs11provider", SOC_UNSUPPORTED},
  { "preferredauthentications", SOC_UNSUPPORTED},
  { "proxyjump", SOC_UNSUPPORTED},
  { "proxyusefdpass", SOC_UNSUPPORTED},
  { "pubkeyacceptedtypes", SOC_PUBKEYACCEPTEDTYPES},
  { "rekeylimit", SOC_UNSUPPORTED},
  { "remotecommand", SOC_UNSUPPORTED},
  { "revokedhostkeys", SOC_UNSUPPORTED},
  { "rhostsrsaauthentication", SOC_UNSUPPORTED},
  { "rsaauthentication", SOC_UNSUPPORTED}, /* SSHv1 */
  { "serveralivecountmax", SOC_UNSUPPORTED},
  { "serveraliveinterval", SOC_UNSUPPORTED},
  { "streamlocalbindmask", SOC_UNSUPPORTED},
  { "streamlocalbindunlink", SOC_UNSUPPORTED},
  { "syslogfacility", SOC_UNSUPPORTED},
  { "tcpkeepalive", SOC_UNSUPPORTED},
  { "updatehostkeys", SOC_UNSUPPORTED},
  { "useprivilegedport", SOC_UNSUPPORTED},
  { "verifyhostkeydns", SOC_UNSUPPORTED},
  { "visualhostkey", SOC_UNSUPPORTED},
  { "clearallforwardings", SOC_NA},
  { "controlmaster", SOC_NA},
  { "controlpersist", SOC_NA},
  { "controlpath", SOC_NA},
  { "dynamicforward", SOC_NA},
  { "escapechar", SOC_NA},
  { "exitonforwardfailure", SOC_NA},
  { "forwardx11", SOC_NA},
  { "forwardx11timeout", SOC_NA},
  { "forwardx11trusted", SOC_NA},
  { "gatewayports", SOC_NA},
  { "ignoreunknown", SOC_NA},
  { "localcommand", SOC_NA},
  { "localforward", SOC_NA},
  { "permitlocalcommand", SOC_NA},
  { "remoteforward", SOC_NA},
  { "requesttty", SOC_NA},
  { "sendenv", SOC_NA},
  { "tunnel", SOC_NA},
  { "tunneldevice", SOC_NA},
  { "xauthlocation", SOC_NA},
  { NULL, SOC_UNKNOWN }
};

enum ssh_config_match_e {
    MATCH_UNKNOWN = -1,
    MATCH_ALL,
    MATCH_CANONICAL,
    MATCH_EXEC,
    MATCH_HOST,
    MATCH_ORIGINALHOST,
    MATCH_USER,
    MATCH_LOCALUSER
};

struct ssh_config_match_keyword_table_s {
    const char *name;
    enum ssh_config_match_e opcode;
};

static struct ssh_config_match_keyword_table_s ssh_config_match_keyword_table[] = {
    { "all", MATCH_ALL },
    { "canonical", MATCH_CANONICAL },
    { "exec", MATCH_EXEC },
    { "host", MATCH_HOST },
    { "originalhost", MATCH_ORIGINALHOST },
    { "user", MATCH_USER },
    { "localuser", MATCH_LOCALUSER },
};

static int ssh_config_parse_line(ssh_session session, const char *line,
    unsigned int count, int *parsing, uint8_t *seen);

static enum ssh_config_opcode_e ssh_config_get_opcode(char *keyword) {
  int i;

  for (i = 0; ssh_config_keyword_table[i].name != NULL; i++) {
    if (strcasecmp(keyword, ssh_config_keyword_table[i].name) == 0) {
      return ssh_config_keyword_table[i].opcode;
    }
  }

  return SOC_UNKNOWN;
}

static char *ssh_config_get_cmd(char **str) {
  register char *c;
  char *r;

  /* Ignore leading spaces */
  for (c = *str; *c; c++) {
    if (! isblank(*c)) {
      break;
    }
  }

  if (*c == '\"') {
    for (r = ++c; *c; c++) {
      if (*c == '\"') {
        *c = '\0';
        goto out;
      }
    }
  }

  for (r = c; *c; c++) {
    if (*c == '\n') {
      *c = '\0';
      goto out;
    }
  }

out:
  *str = c + 1;

  return r;
}

static char *ssh_config_get_token(char **str) {
  register char *c;
  char *r;

  c = ssh_config_get_cmd(str);

  for (r = c; *c; c++) {
    if (isblank(*c) || *c == '=') {
      *c = '\0';
      goto out;
    }
  }

out:
  *str = c + 1;

  return r;
}

static long ssh_config_get_long(char **str, long notfound) {
  char *p, *endp;
  long i;

  p = ssh_config_get_token(str);
  if (p && *p) {
    i = strtol(p, &endp, 10);
    if (p == endp) {
      return notfound;
    }
    return i;
  }

  return notfound;
}

static const char *ssh_config_get_str_tok(char **str, const char *def) {
  char *p;

  p = ssh_config_get_token(str);
  if (p && *p) {
    return p;
  }

  return def;
}

static int ssh_config_get_yesno(char **str, int notfound) {
  const char *p;

  p = ssh_config_get_str_tok(str, NULL);
  if (p == NULL) {
    return notfound;
  }

  if (strncasecmp(p, "yes", 3) == 0) {
    return 1;
  } else if (strncasecmp(p, "no", 2) == 0) {
    return 0;
  }

  return notfound;
}

static void local_parse_file(ssh_session session, const char *filename,
                             int *parsing, uint8_t *seen)
{
  FILE *f;
  char line[MAX_LINE_SIZE] = {0};
  unsigned int count = 0;

  if ((f = fopen(filename, "r")) == NULL) {
    SSH_LOG(SSH_LOG_RARE, "Cannot find file %s to load",
            filename);
    return;
  }

  SSH_LOG(SSH_LOG_PACKET, "Reading additional configuration data from %s", filename);
  while (fgets(line, sizeof(line), f)) {
    count++;
    if (ssh_config_parse_line(session, line, count, parsing, seen) < 0) {
       fclose(f);
       return;
    }
  }

  fclose(f);
  return;
}

#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
static void local_parse_glob(ssh_session session,
                             const char *fileglob,
                             int *parsing,
                             uint8_t *seen)
{
    glob_t globbuf = {
        .gl_flags = 0,
    };
    int rt;
    u_int i;

    rt = glob(fileglob, GLOB_TILDE, NULL, &globbuf);
    if (rt == GLOB_NOMATCH) {
        globfree(&globbuf);
        return;
    } else if (rt != 0) {
        SSH_LOG(SSH_LOG_RARE, "Glob error: %s",
                fileglob);
        globfree(&globbuf);
        return;
    }

    for (i = 0; i < globbuf.gl_pathc; i++) {
        local_parse_file(session, globbuf.gl_pathv[i], parsing, seen);
    }

    globfree(&globbuf);
}
#endif /* HAVE_GLOB HAVE_GLOB_GL_FLAGS_MEMBER */

static enum ssh_config_match_e
ssh_config_get_match_opcode(const char *keyword)
{
    size_t i;

    for (i = 0; ssh_config_match_keyword_table[i].name != NULL; i++) {
        if (strcasecmp(keyword, ssh_config_match_keyword_table[i].name) == 0) {
            return ssh_config_match_keyword_table[i].opcode;
        }
    }

    return MATCH_UNKNOWN;
}

static int
ssh_config_match(char *value, const char *pattern, bool negate)
{
    int ok, result = 0;
    char *lowervalue;

    lowervalue = (value) ? ssh_lowercase(value) : NULL;
    ok = match_pattern_list(lowervalue, pattern, strlen(pattern), 0);
    if (ok <= 0 && negate == true) {
        result = 1;
    } else if (ok > 0 && negate == false) {
        result = 1;
    }
    SSH_LOG(SSH_LOG_TRACE, "%s '%s' against pattern '%s'%s (ok=%d)",
            result == 1 ? "Matched" : "Not matched", value, pattern,
            negate == true ? " (negated)" : "", ok);
    SAFE_FREE(lowervalue);
    return result;
}

static int ssh_config_parse_line(ssh_session session, const char *line,
    unsigned int count, int *parsing, uint8_t *seen)
{
  enum ssh_config_opcode_e opcode;
  const char *p;
  char *s, *x;
  char *keyword;
  char *lowerhost;
  size_t len;
  int i;
  long l;

  x = s = strdup(line);
  if (s == NULL) {
    ssh_set_error_oom(session);
    return -1;
  }

  /* Remove trailing spaces */
  for (len = strlen(s) - 1; len > 0; len--) {
    if (! isspace(s[len])) {
      break;
    }
    s[len] = '\0';
  }

  keyword = ssh_config_get_token(&s);
  if (keyword == NULL || *keyword == '#' ||
      *keyword == '\0' || *keyword == '\n') {
    SAFE_FREE(x);
    return 0;
  }

  opcode = ssh_config_get_opcode(keyword);
  if (*parsing == 1 &&
      opcode != SOC_HOST &&
      opcode != SOC_MATCH &&
      opcode != SOC_INCLUDE &&
      opcode > SOC_UNSUPPORTED) { /* Ignore all unknown types here */
      /* Skip all the options that were already applied */
      if (seen[opcode] != 0) {
          SAFE_FREE(x);
          return 0;
      }
      seen[opcode] = 1;
  }

  switch (opcode) {
    case SOC_INCLUDE: /* recursive include of other files */

      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
#if defined(HAVE_GLOB) && defined(HAVE_GLOB_GL_FLAGS_MEMBER)
        local_parse_glob(session, p, parsing, seen);
#else
        local_parse_file(session, p, parsing, seen);
#endif /* HAVE_GLOB */
      }
      break;

    case SOC_MATCH: {
        bool negate;
        int result = 1;
        size_t args = 0;
        enum ssh_config_match_e opt;

        *parsing = 0;
        do {
            p = ssh_config_get_str_tok(&s, NULL);
            if (p == NULL || p[0] == '\0') {
                break;
            }
            args++;
            SSH_LOG(SSH_LOG_TRACE, "line %d: Processing Match keyword '%s'",
                    count, p);

            /* If the option is prefixed with ! the result should be negated */
            negate = false;
            if (p[0] == '!') {
                negate = true;
                p++;
            }

            opt = ssh_config_get_match_opcode(p);
            switch (opt) {
            case MATCH_ALL:
                p = ssh_config_get_str_tok(&s, NULL);
                if (args == 1 && (p == NULL || p[0] == '\0')) {
                    /* The first argument and end of line */
                    if (negate == true) {
                        result = 0;
                    }
                    break;
                }

                ssh_set_error(session, SSH_FATAL,
                              "line %d: ERROR - Match all can not be combined with "
                              "other Match attributes", count);
                SAFE_FREE(x);
                return -1;

            case MATCH_EXEC:
            case MATCH_ORIGINALHOST:
            case MATCH_LOCALUSER:
                /* Skip one argument */
                p = ssh_config_get_str_tok(&s, NULL);
                args++;
                FALL_THROUGH;
            case MATCH_CANONICAL:
                SSH_LOG(SSH_LOG_WARN, "line: %d: Unsupported Match keyword "
                        "'%s', Ignoring\n", count, p);
                result = 0;
                break;

            case MATCH_HOST:
                /* Here we match only one argument */
                p = ssh_config_get_str_tok(&s, NULL);
                if (p == NULL || p[0] == '\0') {
                    ssh_set_error(session, SSH_FATAL,
                                  "line %d: ERROR - Match host keyword "
                                  "requires argument", count);
                    SAFE_FREE(x);
                    return -1;
                }
                result &= ssh_config_match(session->opts.host, p, negate);
                args++;
                break;

            case MATCH_USER:
                /* Here we match only one argument */
                p = ssh_config_get_str_tok(&s, NULL);
                if (p == NULL || p[0] == '\0') {
                    ssh_set_error(session, SSH_FATAL,
                                  "line %d: ERROR - Match user keyword "
                                  "requires argument", count);
                    SAFE_FREE(x);
                    return -1;
                }
                result &= ssh_config_match(session->opts.username, p, negate);
                args++;
                break;

            case MATCH_UNKNOWN:
            default:
                ssh_set_error(session, SSH_FATAL,
                              "ERROR - Unknown argument '%s' for Match keyword", p);
                SAFE_FREE(x);
                return -1;
            }
        } while (p != NULL && p[0] != '\0');
        if (args == 0) {
            ssh_set_error(session, SSH_FATAL,
                          "ERROR - Match keyword requires an argument");
            SAFE_FREE(x);
            return -1;
        }
        *parsing = result;
        break;
    }
    case SOC_HOST: {
        int ok = 0, result = -1;

        *parsing = 0;
        lowerhost = (session->opts.host) ? ssh_lowercase(session->opts.host) : NULL;
        for (p = ssh_config_get_str_tok(&s, NULL);
             p != NULL && p[0] != '\0';
             p = ssh_config_get_str_tok(&s, NULL)) {
             if (ok >= 0) {
               ok = match_hostname(lowerhost, p, strlen(p));
               if (result == -1 && ok < 0) {
                   result = 0;
               } else if (result == -1 && ok > 0) {
                   result = 1;
               }
            }
        }
        SAFE_FREE(lowerhost);
        if (result != -1) {
            *parsing = result;
        }
        break;
    }
    case SOC_HOSTNAME:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        char *z = ssh_path_expand_escape(session, p);
        if (z == NULL) {
            z = strdup(p);
        }
        ssh_options_set(session, SSH_OPTIONS_HOST, z);
        free(z);
      }
      break;
    case SOC_PORT:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_PORT_STR, p);
        }
        break;
    case SOC_USERNAME:
      if (session->opts.username == NULL) {
          p = ssh_config_get_str_tok(&s, NULL);
          if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_USER, p);
         }
      }
      break;
    case SOC_IDENTITY:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, p);
      }
      break;
    case SOC_CIPHERS:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, p);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, p);
      }
      break;
    case SOC_MACS:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, p);
        ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, p);
      }
      break;
    case SOC_COMPRESSION:
      i = ssh_config_get_yesno(&s, -1);
      if (i >= 0 && *parsing) {
        if (i) {
          ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");
        } else {
          ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "no");
        }
      }
      break;
    case SOC_PROTOCOL:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        char *a, *b;
        b = strdup(p);
        if (b == NULL) {
          SAFE_FREE(x);
          ssh_set_error_oom(session);
          return -1;
        }
        i = 0;
        ssh_options_set(session, SSH_OPTIONS_SSH2, &i);

        for (a = strtok(b, ","); a; a = strtok(NULL, ",")) {
          switch (atoi(a)) {
            case 1:
              break;
            case 2:
              i = 1;
              ssh_options_set(session, SSH_OPTIONS_SSH2, &i);
              break;
            default:
              break;
          }
        }
        SAFE_FREE(b);
      }
      break;
    case SOC_TIMEOUT:
      l = ssh_config_get_long(&s, -1);
      if (l >= 0 && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &l);
      }
      break;
    case SOC_STRICTHOSTKEYCHECK:
      i = ssh_config_get_yesno(&s, -1);
      if (i >= 0 && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &i);
      }
      break;
    case SOC_KNOWNHOSTS:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, p);
      }
      break;
    case SOC_PROXYCOMMAND:
      p = ssh_config_get_cmd(&s);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, p);
      }
      break;
    case SOC_GSSAPISERVERIDENTITY:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, p);
      }
      break;
    case SOC_GSSAPICLIENTIDENTITY:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY, p);
      }
      break;
    case SOC_GSSAPIDELEGATECREDENTIALS:
      i = ssh_config_get_yesno(&s, -1);
      if (i >=0 && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS, &i);
      }
      break;
    case SOC_BINDADDRESS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_BINDADDR, p);
        }
        break;
    case SOC_GLOBALKNOWNHOSTSFILE:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, p);
        }
        break;
    case SOC_LOGLEVEL:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            int value = -1;

            if (strcasecmp(p, "quiet") == 0) {
                value = SSH_LOG_NONE;
            } else if (strcasecmp(p, "fatal") == 0 ||
                    strcasecmp(p, "error")== 0 ||
                    strcasecmp(p, "info") == 0) {
                value = SSH_LOG_WARN;
            } else if (strcasecmp(p, "verbose") == 0) {
                value = SSH_LOG_INFO;
            } else if (strcasecmp(p, "DEBUG") == 0 ||
                    strcasecmp(p, "DEBUG1") == 0) {
                value = SSH_LOG_DEBUG;
            } else if (strcasecmp(p, "DEBUG2") == 0 ||
                    strcasecmp(p, "DEBUG3") == 0) {
                value = SSH_LOG_TRACE;
            }
            if (value != -1) {
                ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &value);
            }
        }
        break;
    case SOC_HOSTKEYALGORITHMS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, p);
        }
        break;
    case SOC_PUBKEYACCEPTEDTYPES:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, p);
        }
        break;
    case SOC_KEXALGORITHMS:
        p = ssh_config_get_str_tok(&s, NULL);
        if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, p);
        }
        break;
    case SOC_GSSAPIAUTHENTICATION:
    case SOC_KBDINTERACTIVEAUTHENTICATION:
    case SOC_PASSWORDAUTHENTICATION:
    case SOC_PUBKEYAUTHENTICATION:
        i = ssh_config_get_yesno(&s, 0);
        if (i>=0 && *parsing) {
            switch(opcode){
            case SOC_GSSAPIAUTHENTICATION:
                ssh_options_set(session, SSH_OPTIONS_GSSAPI_AUTH, &i);
                break;
            case SOC_KBDINTERACTIVEAUTHENTICATION:
                ssh_options_set(session, SSH_OPTIONS_KBDINT_AUTH, &i);
                break;
            case SOC_PASSWORDAUTHENTICATION:
                ssh_options_set(session, SSH_OPTIONS_PASSWORD_AUTH, &i);
                break;
            case SOC_PUBKEYAUTHENTICATION:
                ssh_options_set(session, SSH_OPTIONS_PUBKEY_AUTH, &i);
                break;
            /* make gcc happy */
            default:
                break;
            }
        }
        break;
    case SOC_NA:
      SSH_LOG(SSH_LOG_INFO, "Unapplicable option: %s, line: %d\n",
              keyword, count);
      break;
    case SOC_UNSUPPORTED:
      SSH_LOG(SSH_LOG_RARE, "Unsupported option: %s, line: %d",
              keyword, count);
      break;
    case SOC_UNKNOWN:
      SSH_LOG(SSH_LOG_WARN, "Unknown option: %s, line: %d\n",
              keyword, count);
      break;
    default:
      ssh_set_error(session, SSH_FATAL, "ERROR - unimplemented opcode: %d",
              opcode);
      SAFE_FREE(x);
      return -1;
      break;
  }

  SAFE_FREE(x);
  return 0;
}

/* ssh_config_parse_file */
int ssh_config_parse_file(ssh_session session, const char *filename)
{
  char line[MAX_LINE_SIZE] = {0};
  unsigned int count = 0;
  FILE *f;
  int parsing;
  uint8_t *seen = NULL;

  if ((f = fopen(filename, "r")) == NULL) {
    return 0;
  }

  SSH_LOG(SSH_LOG_PACKET, "Reading configuration data from %s", filename);

  /* Preserve the seen array among invocations throughout the session */
  if (session->opts.options_seen == NULL) {
    seen = calloc(SOC_END - SOC_UNSUPPORTED, sizeof(uint8_t));
    if (seen == NULL) {
      fclose(f);
      ssh_set_error_oom(session);
      return -1;
    }
    session->opts.options_seen = seen;
  } else {
    seen = session->opts.options_seen;
  }

  parsing = 1;
  while (fgets(line, sizeof(line), f)) {
    count++;
    if (ssh_config_parse_line(session, line, count, &parsing, seen) < 0) {
      fclose(f);
      return -1;
    }
  }

  fclose(f);
  return 0;
}
