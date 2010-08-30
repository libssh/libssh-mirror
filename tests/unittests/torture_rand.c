#define LIBSSH_STATIC
#include <libssh/priv.h>
#include <pthread.h>
#include "torture.h"

#define NUM_LOOPS 50000
#define NUM_THREADS 200

static void setup(){
	ssh_init();
}

static void *torture_rand_thread(void *threadid){
	char buffer[12];
	int i;
	int r;
	(void)threadid;
	buffer[0]=buffer[1]=buffer[10]=buffer[11]='X';
	for(i=0;i<NUM_LOOPS;++i){
		r=ssh_get_random(&buffer[2], i%8+1 ,0);
	}
	pthread_exit(NULL);
}

START_TEST(torture_rand_threading)
{
	pthread_t threads[NUM_THREADS];
	int i;
	int err;
	for(i=0;i<NUM_THREADS;++i){
		err=pthread_create(&threads[i],NULL,torture_rand_thread,NULL);
		ck_assert_int_eq(err,0);
	}
	for(i=0;i<NUM_THREADS;++i){
		err=pthread_join(threads[i], NULL);
		ck_assert_int_eq(err,0);
	}
}
END_TEST



Suite *torture_make_suite(void) {
  Suite *s = suite_create("torture_rand");

  torture_create_case_fixture(s, "torture_rand_threading", torture_rand_threading,setup,NULL);

  return s;
}
