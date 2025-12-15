#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

volatile int global_number = 0;
pthread_mutex_t muxlock = PTHREAD_MUTEX_INITIALIZER;
void *incrementer(void *my_int) {
    pthread_mutex_lock(&muxlock);
    global_number++;
    pthread_mutex_unlock(&muxlock);
    return(NULL);
}


int main(int argc, char *argv[]){




    int i;
    pthread_t threads[9999];
    int*x=(int*)malloc(sizeof(int));
    for(i=0;i<10000;i++){
        
        pthread_create(&threads[i],NULL,&incrementer, NULL);
    }
    for(i=0;i<10000;i++){
        void *rv;
        pthread_join(threads[i], &rv); //stores answer in rv
    }
    printf("This value should be 10000: %d\n", global_number);
    return EXIT_SUCCESS;

}



// pthread_mutex_t muxlock = PTHREAD_MUTEX_INITIALIZER;

// void * thread_code(void *arg) {
//   pthread_mutex_lock(&muxlock);
//   global_number = global_number + 1;
//   pthread_mutex_unlock(&muxlock);
//   return NULL;
// }

// int main(void) {
//   pthread_t threads[10];
//   int i;
//   for (i = 0; i < 10; i++) {
//     pthread_create(&threads[i], NULL, &thread_code, NULL);
//   }
//   for (i = 0; i < 10; ++i) {
//     void *rv;
//     pthread_join(threads[i], &rv); 
//   }
//   printf("This value should be 10: %d\n", global_number);
//   return EXIT_SUCCESS;
// }
