#include<stdio.h>
#include<string.h>

#define BUFSIZE 100

int count_words(char *str){

    // returns the number of words in a string

    char c;
    int i=0,count=0;

    
    while(str[i]!='\0'){
        if(str[i]==' ')
            count++;
        i++;
    }
    return count+1;
}

int main(){


    char str[BUFSIZE];

    printf("Enter a string:");
    fgets(str,BUFSIZE,stdin);
    printf("Number of words in the entered string is %d\n",count_words(str));

    return 0;
}