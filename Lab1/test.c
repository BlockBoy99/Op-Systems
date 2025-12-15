#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
   int *my_array = (int *) malloc(1000000 * sizeof(int)); 
   int i;
   for (i = 0; i < 1000000; i++) { 
      my_array[i] = i;
   }
   printf("hello");
   free(my_array);

   
}