#include<stdio.h>

int sum(int m){

    int i,sum=0;

    for(i=1;i<=m;i++){
        sum+=i;
    }

    return sum;
}