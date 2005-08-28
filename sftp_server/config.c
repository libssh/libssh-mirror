/* config.c */
/*
Copyright 2005 Aris Adamantiadis

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

#include "libconfig.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "server.h"
/* shortvar is "port" in "port 22" */

int port=22;
char *dsa=NULL;
char *rsa=NULL;

list *groups;
list *users;
struct group *current_group=NULL;
int group_callback(const char *shortvar, const char *var, const char *arguments, const char *value, lc_flags_t flags, void *extra){
    switch(flags){
        case LC_FLAGS_SECTIONSTART:
            printf("new group %s\n",arguments);
            if(current_group){
                printf("can't include a section into a section\n");
                return LC_CBRET_ERROR;
            }
            if(list_find(groups,arguments)){
                printf("group %s defined twice\n",arguments);
                return LC_CBRET_ERROR;
            }
            current_group=malloc(sizeof(struct group));
            memset(current_group,0,sizeof(struct group));
            groups=list_add(groups,arguments,current_group);
            break;
        case LC_FLAGS_SECTIONEND:
            printf("end of group\n\n");
            current_group=NULL;
            break;
        default:
            printf("%s - %s\n", shortvar, value);
    }
    return LC_CBRET_OKAY;
}

int dir_callback(const char *shortvar, const char *var, const char *arguments, const char *value, lc_flags_t flags, void *extra){
    switch(flags){
        case LC_FLAGS_SECTIONSTART:
            printf("new dir %s\n",arguments);
            break;
        case LC_FLAGS_SECTIONEND:
            printf("end of dir\n\n");
            break;
        default:
            printf("%s - %s\n",shortvar, value);
    }
    return LC_CBRET_OKAY;
}

int parse_config(char *file){
    int r;
    printf("Parsing configuration file %s\n",file);
    lc_register_var("Port",LC_VAR_INT,&port,' ');
    lc_register_var("Hostkeyrsa",LC_VAR_STRING,&rsa,' ');
    lc_register_var("Hostkeydsa",LC_VAR_STRING,&dsa,' ');
    
//    lc_register_var("group", LC_VAR_SECTION, NULL, 0);
    r=lc_register_callback("group",0,LC_VAR_NONE,group_callback,NULL);
    r=lc_register_callback("group.user",0,LC_VAR_UNKNOWN,group_callback,NULL);
    r=lc_register_callback("group.uid",0,LC_VAR_UNKNOWN,group_callback,NULL);
    r=lc_register_callback("group.chroot",0,LC_VAR_UNKNOWN,group_callback,NULL);
    r=lc_register_callback("group.group",0,LC_VAR_UNKNOWN,group_callback,NULL);
//    lc_register_var("dir", LC_VAR_SECTION, NULL, 0);
    r=lc_register_callback("dir",0,LC_VAR_NONE,dir_callback,NULL);
    r=lc_register_callback("dir.list",0,LC_VAR_UNKNOWN,dir_callback,NULL);
    r=lc_register_callback("dir.read",0,LC_VAR_UNKNOWN,dir_callback,NULL);
    r=lc_register_callback("dir.write",0,LC_VAR_UNKNOWN,dir_callback,NULL);

    r=lc_process_file("sftp",file,LC_CONF_APACHE);
    if(r<0)
        printf("lc_process_file=%d,%s\n",r,lc_geterrstr());
    lc_cleanup();
    return 0;
}
