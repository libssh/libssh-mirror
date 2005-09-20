#include <libssh/libssh.h>
#include <libssh/sftp.h>
/* server.h */
/* headers for the sftp server project */
int parse_config(char *file);
char *user_chroot(char *user);
char *user_uid(char *user);
int user_nopassword(char *user);

/* userauth.c */
int do_auth(SSH_SESSION *session);

/* protocol.c */

int sftploop(SSH_SESSION *session, SFTP_SESSION *sftp);

/* list.c */
typedef struct list_struct {
    struct list_struct *next;
    char *key;
    void *data;
} list;

list *list_add(list *ptr, const char *key, void *data);
void *list_find(list *ptr, const char *key);
void list_set(list *ptr, const char *key, void *data);
/* config.c */
extern int port;
extern char *dsa;
extern char *rsa;
struct group {
    list *users;
    char *chroot;
    char *uid;
    char *gid;
    int nopassword;
};

struct dir {
    char *name;
    list *subdir;
    list *List;
    list *Read;
    list *Write;
};

/* acl_* functions returns this : */
/* 1 : operation allowed */
/* 0 : operation denied */
int acl_open(char *file, int mode);
int acl_opendir(char *dir);
int acl_stat(char *file);
int acl_rm(char *file);
int acl_rmdir(char *dir);
int acl_mv(char *from, char *to);
int acl_mkdir(char *dir);
int acl_symlink(char *from, char *to);
int acl_setstat(char *file);

/* still experimental */

#define BLOCKLEN 65536

/* here is how it works : */
/* the buffer is BLOCKLEN long. */
/* Bytes is the number of valid bytes into the buffer. these valid bytes */
/* begin at &buffer[0]  */
/* buffer+start is mapped at offset. */
/* thus, there are (bytes-start) bytes ready to be read. */

struct file {
    int fd;
    u64 offset;
    unsigned char buffer[BLOCKLEN];
    int bytes;
    int start; // number of the first byte pointed by offset
    int mode;
    int eof;
    int delayed_write; /* there are data into the buffer to be read */
    int write_end; /* end of data, relative to buffer[0] */
    int write_start; /* begining of data */
};


struct file *file_open(char *filename, int mode);
int file_sync(struct file *file);
int file_close(struct file *file);


