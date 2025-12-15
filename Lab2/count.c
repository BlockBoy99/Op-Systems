#include<stdio.h>
#include<string.h>

int count_words(char *str){
    char c;
    int i=0, count=0;

    while(str[i]!='\0'){
        if(str[i]==' '){
            count++;
        }
        i++;
        
    }
    return(count+1);
}
int count_words2(char *str){
    int count=0;
    char *p =str;

    // Skip leading spaces
    while (*p == ' ')
        p++;

    while(*p!='\0'){
        count++;
        char *space=strstr(p," ");
        if(space==NULL){
            break;
        }
        p=space+1;
    }
    return(count);
}
int main(){


    char str[100];

    printf("Enter a string:");
    fgets(str,100,stdin);    // this function reads a line or at most 99 bytes from stdin file stream that represents the keyboard
    printf("Number of words in the entered string is %d\n",count_words2(str));

    return 0;
}
