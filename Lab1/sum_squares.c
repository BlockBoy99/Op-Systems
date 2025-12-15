#include<stdio.h>

int sum_squares(int m){

    int i,sum=0;

    for(i=1;i<=m;i++){
        sum+=i*i;
    }

    return sum;
}