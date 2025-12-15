#include <stdio.h> // Includes the stdio.h library 
#include <stdbool.h>


//EXERCISE 4

int main() {
    int size;
    int* ptr;
    int temp;
    printf("What is the size of the integer: ");
    scanf("%d", &size); // Read an integer from user input
    ptr = (int *) malloc(size*sizeof(int));
    if (ptr==NULL){
        printf("Memory not allocated.\n");
    } else{
        printf("Memory allocated. \n");
        for(int i=0; i <size;i++){
            printf("Enter your input: ");
            scanf("%d",&temp); // Read an integer from user input
            ptr[i]=temp;
        }
        for(int i=0; i<size; i++){
            printf("%d ",ptr[i]);
        }
    }
}

//EXERCISE 3

// write the code for the sort() function that sorts an integer array in ascending order


// int main() {
//     int x[]={4,1,4,3,10,5};
//     int i;

//     sort(x,6); // sort() function sorts the array x in ascending order

//     printf("The sorted array is as follows:\n");

//     for(i=0; i<6; i++){
//         printf("%d ",x[i]);
//     }
//     printf("\n");
//     return 0;
// }
// void sort(int x[], int length ){
//     bool end=false;
//     int count=0;
//     while(!end){
//         count=0;
//         for(int i=0;i<length-1;i++){
        
//             if(x[i]>x[i+1]){
//                 swap(&x[i],&x[i+1]);
//                 count=1;
//             }
//         }
//         if(count!=1){
//             end=true;
//         }
//     }
// }
// void swap(int *a,int *b ){
//     int tempValue=*a;
//     *a=*b;
//     *b=tempValue;
//  }


// EXERCISE 2: SWAP FUNCTION

// write the code for the function swap() that would swap the values of two integers

// int main(int argc, char *argv[]) {
//    int val_a = 50;
//    int val_b = 20;
//    swap(&val_a,&val_b);
//    // call the swap() function correctly, swap() should swap the values stored in val_a and val_b so
//    // that the swapped values of val_a and val_b are printed in the next two lines
//    printf("val_a is %d (should be 20)\n", val_a);
//    printf("val_b is %d (should be 50)\n", val_b);
//   return 0;
// }
// void swap(int *a,int *b ){
//     int tempValue=*a;
//     *a=*b;
//     *b=tempValue;
// }


//EXERCISE 1: PRINTING PRIME NUMBERS
// int main() {
//     int n;
//     printf("Enter a positive integer: ");
//     scanf("%d", &n); // Read an integer from user input
//     int i;
//     for(i=1;i<n;i++){
//         if(isPrime(i)){
//             printf("%d\n",i);
//         }
//     }
// }
// int isPrime(int num){
//     int j;
//     for(j=2;j<num;j++){
//         if(num%j==0){
//             return(0);
//         }
//     }
//     return (1);
// }

//POINTERS AND ARRAYS
// int main(int argc, char *argv[]) {
//     int *a_pointer;
//     int a_value=5;
//     int x[]={10,1,2,5,-3};
//     a_pointer = &a_value; //& gets adress of a value
//     int i;

//    printf("The value of a_value is %d\n", a_value); // prints the value of the variable a_value
//    printf("The value of the pointer is %p,\n",a_pointer); // prints the address of the variable a_value
//    printf("The value pointed by the pointer is %d,\n",*a_pointer); // prints the value of the variable a_value

//    *a_pointer = 10; //stores 10 in the address pointed by a_pointer, which is the address of a_value

//    printf("The value of a_value is now %d\n", a_value); // the value of a_value will be changed

//    printf("The start address of the array x is %p\n",&x); // prints the base address of the array x
//    printf("The address of the first element is %p\n",&x[0]); // also prints the same
//    for(i=0;i <5; i++){
//      printf("Value stored in address %p is %d\n",(x+i),x[i]);  // shows that array elements are stored in contiguous locations
//    }
//    printf("Size of each integer is %lu bytes\n",sizeof(int));  // the address of each location in array x differs by this amount from its previous location

//    return 0;
// }





//FACTORIAL
// int factorial(int m){  // computes the factorial of a positive integer m

//     int i,prod=1;

//     for(i=2; i <=m; i++){
//         prod=prod*i;
//     }
//     return prod;
// }

// int main(){

//     int n;

//     printf("Enter a positive integer:");
//     scanf("%d",&n); // scanf() scans the integer entered by the user

//     printf("The factoral of %d is %d\n",n,factorial(n));
//     return 0;
// }
 


//HELLOWORLD
// int main(int argc, char *argv[]) { // main method is called when program is run
//    printf("Hello, world!\n");      // Use the printf function from stdio.h to print a string to the terminal
//    return 0;                       // return code zero means no problems occurred
// }

