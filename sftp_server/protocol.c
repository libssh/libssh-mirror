/* protocol dependant part of Mercurius */
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

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libssh/server.h>
#include <dirent.h>
#include <errno.h>

#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "server.h"

#define TYPE_DIR 1
#define TYPE_FILE 1
struct sftp_handle {
    int type;
    int offset;
    char *name;
    int eof;
    DIR *dir;
    FILE *file;
};

int reply_status(SFTP_CLIENT_MESSAGE *msg){
    switch(errno){
        case EACCES:
            return sftp_reply_status(msg,SSH_FX_PERMISSION_DENIED,
                                     "permission denied");
        case ENOENT:
            return sftp_reply_status(msg,SSH_FX_NO_SUCH_FILE,
                                     "no such file or directory");
        case ENOTDIR:
            return sftp_reply_status(msg,SSH_FX_FAILURE,
                                     "not a directory");
        default:
            return sftp_reply_status(msg,SSH_FX_FAILURE,NULL);
    }
}

void handle_opendir(SFTP_CLIENT_MESSAGE *msg){
    DIR *dir=opendir(msg->filename);
    struct sftp_handle *hdl;
    STRING *handle;
    if(!dir){
        reply_status(msg);
        return;
    }
    hdl=malloc(sizeof(struct sftp_handle));
    memset(hdl,0,sizeof(struct sftp_handle));
    hdl->type=TYPE_DIR;
    hdl->offset=0;
    hdl->dir=dir;
    hdl->name=strdup(msg->filename);
    handle=sftp_handle_alloc(msg->sftp,hdl);
    sftp_reply_handle(msg,handle);
    free(handle);
}

SFTP_ATTRIBUTES *attr_from_stat(struct stat *statbuf){
    SFTP_ATTRIBUTES *attr=malloc(sizeof(SFTP_ATTRIBUTES));
    memset(attr,0,sizeof(*attr));
    attr->size=statbuf->st_size;
    attr->uid=statbuf->st_uid;
    attr->gid=statbuf->st_gid;
    attr->permissions=statbuf->st_mode;
    attr->atime=statbuf->st_atime;
    attr->mtime=statbuf->st_mtime;
    attr->flags=SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
    return attr;
}

int handle_stat(SFTP_CLIENT_MESSAGE *msg,int follow){
    struct stat statbuf;
    SFTP_ATTRIBUTES *attr;
    int ret;
    if(follow)
        ret=stat(msg->filename,&statbuf);
    else 
        ret=lstat(msg->filename,&statbuf);
    if(ret<0){
        reply_status(msg);
        return 0;
    }
    attr=attr_from_stat(&statbuf);
    sftp_reply_attr(msg, attr);
    sftp_attributes_free(attr);
    return 0;
}

char *long_name(char *file, struct stat *statbuf){
    static char buf[256];
    char buf2[100];
    int mode=statbuf->st_mode;
    char *time,*ptr;
    strcpy(buf,"");
    switch(mode & S_IFMT){
        case S_IFDIR:
            strcat(buf,"d");
            break;
        default:
            strcat(buf,"-");
            break;
    }
    /* user */
    if(mode & 0400)
        strcat(buf,"r");
    else
        strcat(buf,"-");
    if(mode & 0200)
        strcat(buf,"w");
    else
        strcat(buf,"-");
    if(mode & 0100){
        if(mode & S_ISUID)
            strcat(buf,"s");
        else
            strcat(buf,"x");
    } else
        strcat(buf,"-");
        /*group*/
        if(mode & 040)
            strcat(buf,"r");
        else
            strcat(buf,"-");
        if(mode & 020)
            strcat(buf,"w");
        else
            strcat(buf,"-");
        if(mode & 010)
            strcat(buf,"x");
        else
            strcat(buf,"-");
        /* other */
        if(mode & 04)
            strcat(buf,"r");
        else
            strcat(buf,"-");
        if(mode & 02)
            strcat(buf,"w");
        else
            strcat(buf,"-");
        if(mode & 01)
            strcat(buf,"x");
        else
            strcat(buf,"-");
        strcat(buf," ");
        snprintf(buf2,sizeof(buf2),"%3d %d %d %d",(int)statbuf->st_nlink,
                 (int)statbuf->st_uid,(int)statbuf->st_gid,(int)statbuf->st_size);
        strcat(buf,buf2);
        time=ctime(&statbuf->st_mtime)+4;
        if((ptr=strchr(time,'\n')))
            *ptr=0;
        snprintf(buf2,sizeof(buf2)," %s %s",time,file);
    // +4 to remove the "WED "
        strcat(buf,buf2);
        return buf;
}

int handle_readdir(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    SFTP_ATTRIBUTES *attr;
    struct dirent *dir;
    char *longname;
    struct stat statbuf;
    char file[1024];
    int i;
    if(!handle || handle->type!=TYPE_DIR){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    for(i=0; !handle->eof && i<50;++i){
        dir=readdir(handle->dir);
        if(!dir){
            handle->eof=1;
            break;
        }
        snprintf(file,sizeof(file),"%s/%s",handle->name,
                 dir->d_name);
        if(lstat(file,&statbuf)){
            memset(&statbuf,0,sizeof(statbuf));
        }
        attr=attr_from_stat(&statbuf);
        longname=long_name(dir->d_name,&statbuf);
        sftp_reply_names_add(msg,dir->d_name,longname,attr);
        sftp_attributes_free(attr);
    }
    /* if there was at least one file, don't send the eof yet */
    if(i==0 && handle->eof){
        sftp_reply_status(msg,SSH_FX_EOF,NULL);
        return 0;
    }
    sftp_reply_names(msg);
    return 0;
}

int handle_read(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    u32 len=msg->len;
    void *data;
    int r;
    if(!handle || handle->type!=TYPE_FILE){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    if(len>(2<<15)){
        /* 32000 */
        len=2<<15;
    }
    data=malloc(len);
    fseeko(handle->file,msg->offset,SEEK_SET);
    r=fread(data,1,len,handle->file);
    ssh_say(2,"read %d bytes\n",r);
    if(r<=0 && (len>0)){
        if(feof(handle->file)){
            sftp_reply_status(msg,SSH_FX_EOF,"End of file");
        } else {
            reply_status(msg);
        }
        return 0;
    }
    sftp_reply_data(msg,data,r);
    free(data);
    return 0;
}

int handle_write(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    u32 len=string_len(msg->data);
    int r;
    if(!handle || handle->type!=TYPE_FILE){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    fseeko(handle->file,msg->offset,SEEK_SET);
    do {
        r=fwrite(string_data(msg->data),1,len,handle->file);
        ssh_say(2,"wrote %d bytes\n",r);
        if(r<=0 && (msg->data>0)){
            reply_status(msg);
        return 0;
        }
        len-=r;
    } while (len>0);
    sftp_reply_status(msg,SSH_FX_OK,"");
    return 0;
}

int handle_close(SFTP_CLIENT_MESSAGE *msg){
    struct sftp_handle *handle=sftp_handle(msg->sftp,msg->handle);
    if(!handle){
        sftp_reply_status(msg,SSH_FX_BAD_MESSAGE,"invalid handle");
        return 0;
    }
    sftp_handle_remove(msg->sftp,handle);
    if(handle->type==TYPE_DIR){
        closedir(handle->dir);
    } else {
        fclose(handle->file);
    }
    if(handle->name)
        free(handle->name);
    free(handle);
    sftp_reply_status(msg,SSH_FX_OK,NULL);
    return 0;
}

int handle_open(SFTP_CLIENT_MESSAGE *msg){
    int flags=0;
    int fd;
    FILE *file;
    char *mode="r";
    struct sftp_handle *hdl;
    STRING *handle;
    if(msg->flags & SSH_FXF_READ)
        flags |= O_RDONLY;
    if(msg->flags & SSH_FXF_WRITE)
        flags |= O_WRONLY;
    if(msg->flags & SSH_FXF_APPEND)
        flags |= O_APPEND;
    if(msg->flags & SSH_FXF_TRUNC)
        flags |= O_TRUNC;
    if(msg->flags & SSH_FXF_EXCL)
        flags |= O_EXCL;
    if(msg->flags & SSH_FXF_CREAT)
        flags |= O_CREAT;
    fd=open(msg->filename,flags,msg->attr->permissions);
    if(fd<0){
        reply_status(msg);
        return 0;
    }
    switch(flags& (O_RDONLY | O_WRONLY | O_APPEND | O_TRUNC)){
        case O_RDONLY:
            mode="r";
            break;
        case (O_WRONLY|O_RDONLY):
            mode="r+";
            break;
        case (O_WRONLY|O_TRUNC):
            mode="w";
            break;
        case (O_WRONLY | O_RDONLY | O_APPEND):
            mode="a+";
            break;
        default:
            switch(flags & (O_RDONLY | O_WRONLY)){
                case O_RDONLY:
                    mode="r";
                    break;
                case O_WRONLY:
                    mode="w";
                    break;
            }
    }
    file=fdopen(fd,mode);
    hdl=malloc(sizeof(struct sftp_handle));
    memset(hdl,0,sizeof(struct sftp_handle));
    hdl->type=TYPE_FILE;
    hdl->offset=0;
    hdl->file=file;
    hdl->name=strdup(msg->filename);
    handle=sftp_handle_alloc(msg->sftp,hdl);
    sftp_reply_handle(msg,handle);
    free(handle);
    return 0;
}

int sftploop(SSH_SESSION *session, SFTP_SESSION *sftp){
    SFTP_CLIENT_MESSAGE *msg;
    char buffer[PATH_MAX];
    do {
        msg=sftp_get_client_message(sftp);
        if(!msg)
            break;
        switch(msg->type){
            case SFTP_REALPATH:
                ssh_say(1,"client realpath : %s\n",msg->filename);
                realpath(msg->filename,buffer);
                ssh_say(2,"responding %s\n",buffer);
                sftp_reply_name(msg, buffer, NULL);
                break;
            case SFTP_OPENDIR:
                ssh_say(1,"client opendir(%s)\n",msg->filename);
                handle_opendir(msg);
                break;
            case SFTP_LSTAT:
            case SFTP_STAT:
                ssh_say(1,"client stat(%s)\n",msg->filename);
                handle_stat(msg,msg->type==SFTP_STAT);
                break;
            case SFTP_READDIR:
                ssh_say(1,"client readdir\n");
                handle_readdir(msg);
                break;
            case SFTP_CLOSE:
                ssh_say(1,"client close\n");
                handle_close(msg);
                break;
            case SFTP_OPEN:
                ssh_say(1,"client open(%s)\n",msg->filename);
                handle_open(msg);
                break;
            case SFTP_READ:
                ssh_say(1,"client read(off=%lld,len=%d)\n",msg->offset,msg->len);
                handle_read(msg);
                break;
            case SFTP_WRITE:
                ssh_say(1,"client write(off=%lld len=%d)\n)\n",msg->offset,string_len(msg->data));
                handle_write(msg);
                break;
            case SFTP_SETSTAT:
            case SFTP_FSETSTAT:
            case SFTP_REMOVE:
            case SFTP_MKDIR:
            case SFTP_RMDIR:
            case SFTP_FSTAT:
            case SFTP_RENAME:
            case SFTP_READLINK:
            case SFTP_SYMLINK:
            default:
                ssh_say(1,"Unknown message %d\n",msg->type);
                sftp_reply_status(msg,SSH_FX_OP_UNSUPPORTED,"Unsupported message");
        }
        sftp_client_message_free(msg);
    } while (1);
    if(!msg)
        return 1;
    return 0;
}
