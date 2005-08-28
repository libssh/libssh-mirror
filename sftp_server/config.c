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
#include <stdlib.h>
#include "server.h"
/* shortvar is "port" in "port 22" */

int port=22;
char *dsa=NULL;
char *rsa=NULL;

list *groups;
list *users;
struct dir *root_dir=NULL;
/* users is a list of users. The key of this list is the user name.
 the data of the list is a list of groups. both data & key from this list
 is the group name */
struct group *current_group=NULL;
char *current_group_name;
int add_user(char *user){
    list *groups_from_user;
//    list *the_user;
    printf("add_user(%s)\n",user);
    if(!list_find(current_group->users,user)){
        current_group->users=list_add(current_group->users,user,strdup(user));
    }
    groups_from_user=list_find(users,user);
    if(!groups_from_user){
        // the user isn't registered yet
        groups_from_user=list_add(NULL,current_group_name,current_group_name);
        users=list_add(users,user,groups_from_user);
    } else {
    // add the group name to the list of groups the user is bound to.
        if(!list_find(groups_from_user,current_group_name)) // don't add it if it is already set
            list_set(users,user,list_add(groups_from_user,current_group_name,current_group_name));
    }
    return 0;
}

int add_group(char *group){
    struct group *grp=list_find(groups,group);
    list *usr;
    if(!grp){
        printf("no such group %s\n",group);
        return -1;
    }
    usr=grp->users;
    while(usr){
        add_user(usr->key);
        usr=usr->next;
    }
    return 0;
}

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
            current_group_name=strdup(arguments);
            break;
        case LC_FLAGS_SECTIONEND:
            printf("end of group\n\n");
            current_group=NULL;
            break;
        default:
            printf("%s - %s\n", shortvar, value);
            if(!strcasecmp(shortvar,"user")){
                char *ptr;
                char *user=(char *)value;
                do{
                    ptr=strchr(user,',');
                    if(ptr){
                        *ptr=0;
                        ++ptr;
                    }
                    while(*user==' ')
                        ++user;
                    add_user(user);
                    user=ptr;
                } while (user);
            }
            if(!strcasecmp(shortvar,"group")){
                char *ptr;
                char *group=(char *)value;
                do{
                    ptr=strchr(group,',');
                    if(ptr){
                        *ptr=0;
                        ++ptr;
                    }
                    while(*group==' ')
                        ++group;
                    add_group(group);
                    group=ptr;
                } while (group);
            }
            if(!strcasecmp(shortvar,"uid")){
                current_group->uid=strdup(value);
            }
            if(!strcasecmp(shortvar,"gid")){
                current_group->gid=strdup(value);
            }
            if(!strcasecmp(shortvar,"chroot")){
                current_group->chroot=strdup(value);
            }
    }
    return LC_CBRET_OKAY;
}
struct dir *create_directory(const char *directory);
struct dir *current_dir=NULL;
int append_groups(list **plist, const char *groups){
    char *begin=strdup(groups);
    char *ptr;
    char *grp=begin;
    do{
        ptr=strchr(grp,',');
        if(ptr){
            *ptr=0;
            ++ptr;
        }
        while(*grp==' ')
            ++grp;
        if(!list_find(*plist,grp))
            *plist=list_add(*plist,grp,strdup(grp));
        grp=ptr;
    } while (grp);
    return 0;
}

int dir_callback(const char *shortvar, const char *var, const char *arguments, const char *value, lc_flags_t flags, void *extra){
    switch(flags){
        case LC_FLAGS_SECTIONSTART:
            if(current_dir){
                printf("Cannot define a directory into a directory !\n");
                return LC_CBRET_ERROR;
            }
            current_dir=create_directory(arguments);
            break;
        case LC_FLAGS_SECTIONEND:
            current_dir=NULL;
            break;
        default:
            if(!strcasecmp(shortvar,"list"))
                append_groups(&current_dir->List,value);
            if(!strcasecmp(shortvar,"read"))
                append_groups(&current_dir->Read,value);
            if(!strcasecmp(shortvar,"write"))
                append_groups(&current_dir->Write,value);
//            printf("%s - %s\n",shortvar, value);
    }
    return LC_CBRET_OKAY;
}

void list_config(){
    list *ptr=groups;
    list *user;
    printf("listing groups\n");
    while(ptr){
        printf("group %s\n",ptr->key);
        user=((struct group *)ptr->data)->users;
        while(user){
            printf("  user %s\n",user->key);
            user=user->next;
        }
        ptr=ptr->next;
    }
    printf("listing users\n");
    user=users;
    while(user){
        printf("user %s\n",user->key);
        ptr=user->data;
        while(ptr){
            printf("  group %s\n",ptr->key);
            ptr=ptr->next;
        }
        user=user->next;
    }
}

char **cut_directory(const char *dir){
    char *tmp=strdup(dir);
    char *ptr;
    char *ret[128];
    char **answer;
    int i=0;
    while(tmp && *tmp && i<128){
        while(*tmp=='/')
            ++tmp;
        ptr=strchr(tmp,'/');
        if(ptr){
            *ptr=0;
            ++ptr;
        }
        ret[i]=strdup(tmp);
        tmp=ptr;
        i++;
    }
    answer=malloc((i+1)*sizeof(char *));
    memcpy(answer,ret,sizeof(char *)*i);
    answer[i]=NULL;
    return answer;
}

struct dir *dir_new(){
    struct dir *dir=malloc(sizeof(struct dir));
    memset(dir,0,sizeof(*dir));
    return dir;
}
/* it doesn't really create the directory. it makes the tree to the directory
 * and returns a link to the last node */
struct dir *create_directory(const char *directory){
    char **tokens=cut_directory(directory);
    int i=0;
    struct dir *dir,*ptr;
    if(!root_dir){
        root_dir=dir_new();
        root_dir->name="";
    }
    dir=root_dir;
    for(i=0;tokens[i];++i){
        ptr=list_find(dir->subdir,tokens[i]);
        if(!ptr){
            ptr=dir_new();
            ptr->name=strdup(tokens[i]);
            dir->subdir=list_add(dir->subdir,tokens[i],ptr);
        }
        dir=ptr;
    }
    for(i=0;tokens[i];++i)
        free(tokens[i]);
    free(tokens);
    return dir;
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
    list_config();
    return 0;
}
