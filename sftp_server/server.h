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

