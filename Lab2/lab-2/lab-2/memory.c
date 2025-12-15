#include <stdlib.h>

int main(int argc, char *argv[]) {
   int *array_of_ints = (int *) malloc(sizeof(int) * 10);
   int i;
   for (i = 0; i < 10; i++) {
      array_of_ints[i] = i;
   }
  free(array_of_ints);
}
