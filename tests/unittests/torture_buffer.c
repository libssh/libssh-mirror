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

/* test the behavior of buffer_prepend_data
 */
START_TEST (torture_buffer_prepend)
{
  uint32_t v;
  buffer_add_data(buffer,"abcdef",6);
  buffer_prepend_data(buffer,"xyz",3);
  ck_assert_int_eq(buffer_get_rest_len(buffer),9);
  ck_assert_int_eq(memcmp(buffer_get_rest(buffer), "xyzabcdef", 9), 0);
// Now remove 4 bytes and see if we can replace them
  buffer_get_u32(buffer,&v);
  ck_assert_int_eq(buffer_get_rest_len(buffer),5);
  ck_assert_int_eq(memcmp(buffer_get_rest(buffer), "bcdef", 5), 0);
  buffer_prepend_data(buffer,"aris",4);
  ck_assert_int_eq(buffer_get_rest_len(buffer),9);
  ck_assert_int_eq(memcmp(buffer_get_rest(buffer), "arisbcdef", 9), 0);
  /* same thing but we add 5 bytes now */
  buffer_get_u32(buffer,&v);
  ck_assert_int_eq(buffer_get_rest_len(buffer),5);
  ck_assert_int_eq(memcmp(buffer_get_rest(buffer), "bcdef", 5), 0);
  buffer_prepend_data(buffer,"12345",5);
  ck_assert_int_eq(buffer_get_rest_len(buffer),10);
  ck_assert_int_eq(memcmp(buffer_get_rest(buffer), "12345bcdef", 10), 0);

}
END_TEST


Suite *torture_make_suite(void) {
  Suite *s = suite_create("libssh_buffer");

  torture_create_case_fixture(s, "torture_growing_buffer",
            torture_growing_buffer, setup, teardown);
  torture_create_case_fixture(s, "torture_growing_buffer_shifting",
            torture_growing_buffer_shifting, setup, teardown);
  torture_create_case_fixture(s, "torture_buffer_prepend",
            torture_buffer_prepend, setup, teardown);
  return s;
}

