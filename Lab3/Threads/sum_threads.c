#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void *sum_runner(void *limit) {
    int *n=(int *) limit;
    int *sum=(int *) malloc(sizeof(int));
    *sum=(*n)*((*n)+1)/2;
	return(sum);
}
int main(int argc, char *argv[]){
    int i;
    int *ans;
    if(argc<=1){
        printf("Error! Usage: ./sum_thread <num>\n"); // Gives an error msg when no numbers are entered
    } else{
        int *limit=(int *)malloc(sizeof(int)* argc); // stores the limits
        pthread_t *threads= (pthread_t *)malloc(argc*sizeof(pthread_t));
        //create threads
        for(i=0;i<argc-1;i++){
            limit[i]=atoi(argv[1+i]);
            pthread_create(&threads[i],NULL,&sum_runner, (void *)&limit[i]);

        }
        for(i=0;i<argc-1;i++){

            pthread_join(threads[i], (void **)&ans);
            printf("Sum of integers up to %d is %d\n", limit[i],*ans);
            free(ans);

        }
        free(limit);
        free(threads);

    }
    return(0);
}
