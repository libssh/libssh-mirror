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
struct group {
    list *users;
    char *chroot;
    int uid;
    int gid;
};
