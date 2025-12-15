#include<stdio.h>
#include<stdlib.h> // required for the exit() function

#define BUFSIZE 10

int main(){

    FILE *fptr1=fopen("./textfile1.txt","r");
    FILE *fptr2=fopen("./textfile2.txt","w");

    if(fptr1==NULL||fptr2==NULL){
        fprintf(stderr,"Error opening file\n");
        exit(1);
    }

    char str[BUFSIZE];

    while(fgets(str,BUFSIZE,fptr1)!=NULL){
        fprintf(fptr2,"%s",str);
    }
    fclose(fptr1);
    fclose(fptr2);
    return 0;

}