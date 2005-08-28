/* server.h */
/* headers for the sftp server project */
int parse_config(char *file);

typedef struct list_struct {
    struct list_struct *next;
    char *key;
    void *data;
} list;

list *list_add(list *ptr, const char *key, void *data);
void *list_find(list *ptr, const char *key);
void list_set(list *ptr, const char *key, void *data);

struct group {
    list *users;
    char *chroot;
    char *uid;
    char *gid;
};

struct dir {
    char *name;
    list *subdir;
    list *List;
    list *Read;
    list *Write;
};

