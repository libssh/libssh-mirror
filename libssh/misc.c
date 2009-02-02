/* misc.c */
/* some misc routines than aren't really part of the ssh protocols but can be useful to the client */

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

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef _WIN32
#define _WIN32_IE 0x0400 //SHGetSpecialFolderPath
#include <shlobj.h>
#include <winsock2.h>
#else
#include <pwd.h>
#endif

#include "libssh/priv.h"

#ifndef _WIN32
char *ssh_get_user_home_dir(void) {
    static char szPath[PATH_MAX] = {0};
    struct passwd *pwd = NULL;

    pwd = getpwuid(getuid());
    if (pwd == NULL) {
      return NULL;
    }

    snprintf(szPath, PATH_MAX - 1, "%s", pwd->pw_dir);

    return szPath;
}

#else /* _WIN32 */

char *ssh_get_user_home_dir(void) {
	static char szPath[MAX_PATH];
	if (SHGetSpecialFolderPathA(NULL, szPath, CSIDL_PROFILE, TRUE))
		return szPath;
	else
		return NULL;
}

#endif

/* we have read access on file */
int ssh_file_readaccess_ok(char *file){
    if(!access(file,R_OK))
        return 1;
    return 0;
}

u64 ntohll(u64 a){
#ifdef WORDS_BIGENDIAN
    return a;
#else
    u32 low=a & 0xffffffff;
    u32 high = a >> 32 ;
    low=ntohl(low);
    high=ntohl(high);
    return (( ((u64)low) << 32) | ( high));
#endif
}
