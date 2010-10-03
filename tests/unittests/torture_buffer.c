#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/buffer.h"

ssh_buffer buffer;
#define LIMIT (8*1024*1024)

static void setup(void) {
    buffer=ssh_buffer_new();
}

static void teardown(void) {
  ssh_buffer_free(buffer);
}

/* test if the continuously growing buffer size never exceeds 2 time its
 * real capacity
 */
START_TEST (torture_growing_buffer)
{
  int i;
  for(i=0;i<LIMIT;++i){
    buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(buffer_get_rest_len(buffer) * 2 < buffer->allocated){
        ck_assert(buffer_get_rest_len(buffer) * 2 >= buffer->allocated);
      }
    }
  }
}
END_TEST

/* test if the continuously growing buffer size never exceeds 2 time its
 * real capacity, when we remove 1 byte after each call (sliding window)
 */
START_TEST (torture_growing_buffer_shifting)
{
  int i;
  unsigned char c;
  for(i=0; i<1024;++i){
    buffer_add_data(buffer,"S",1);
  }
  for(i=0;i<LIMIT;++i){
    buffer_get_u8(buffer,&c);
    buffer_add_data(buffer,"A",1);
    if(buffer->used >= 128){
      if(buffer_get_rest_len(buffer) * 4 < buffer->allocated){
        ck_assert(buffer_get_rest_len(buffer) * 4 >= buffer->allocated);
        return;
      }
    }
  }
}
END_TEST

Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_buffer");

  torture_create_case_fixture(s, "torture_growing_buffer",
            torture_growing_buffer, setup, teardown);
  torture_create_case_fixture(s, "torture_growing_buffer_shifting",
            torture_growing_buffer_shifting, setup, teardown);

  return s;
}

