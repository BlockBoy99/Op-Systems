#include<stdio.h>
#include<stdbool.h>
#include<math.h>




int prime(){

    int n;
    bool prime;
    int sum=0;

    printf("Enter a positive integer:\n");
    scanf("%d",&n);

    for(int i=2;i<n;i++){
        prime=true;
        for (int j=2;j<=ceil(sqrt(n));j++){
            if(n%j==0){
                prime=false;
            }
        }
        if (prime=true){
            sum=sum+i;
        }
    }

    printf("%d \n",sum);
    return 0;
}
