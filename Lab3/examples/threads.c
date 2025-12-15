#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

struct thread_args {
  unsigned int threadnum;
};

struct thread_return {
  unsigned int return_value;
};

void *thread_code(void *arg) {
  char *message = NULL;
  struct thread_args * args = (struct thread_args *) arg;
  switch(args->threadnum) {
    case 0: message = "Hello!"; break;
    case 1: message = "Is it me you're looking for?"; break;
    case 2: message = "I can see it in your eyes."; break;
    case 3: message = "I can see it in your smile"; break;
    case 4: message = "I've run out of Lionel Richie lyrics"; break;
    case 5: message = "Some words"; break;
    case 6: message = "Some more words"; break;
    case 7: message = "Surplus words"; break;
    case 8: message = "Extra words"; break;
    case 9: message = "Final installment of words."; break;
    default: message = "Unsupported thread"; break;
  }
  printf("Thread %d says: '%s'\n", args->threadnum, message);
  free(arg);
  return NULL;
}

int main(void) {
  pthread_t threads[10];
  int i;
  for (i = 0; i < 10; i++) {
    struct thread_args *args = malloc(sizeof(struct thread_args));
    args->threadnum = i;
    pthread_create(&threads[i], NULL, &thread_code, (void *) args);
  }
  for (i = 0; i < 10; ++i) {
    void *rv;
    pthread_join(threads[i], &rv); 
  }
  return EXIT_SUCCESS;
}
