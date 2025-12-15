#include <stdio.h>
#include <stdlib.h>
struct node {
  struct node * next;
  long long item;
};

struct queue{ // data structure for queue
    struct node *head;
    struct node *tail;
};
struct queue *create_queue(void){ //create a qeue and return pointer
    struct queue *q= (struct queue *) malloc(sizeof(struct queue));
    q->head=NULL;
    q->tail=NULL;
    return(q);
}
int isempty(struct queue *q){
    if(q->head==NULL){
        return(1);
    }
    return(0);
}
void enqueue(struct queue *q, long long item){
    struct node *new_node=(struct node*) malloc(sizeof(struct node));
    new_node-> item=item;
    new_node->next=NULL;
    if(!isempty(q)){
        q->tail->next=new_node;
        q->tail=new_node;
    } else{
        q->head=new_node;
        q->tail=new_node;
    }
}

void dequeue(struct queue *q){
    if(isempty(q)){
        printf("Error: attempt to dequeue from an empty queue");
    } else{
        struct node *temp_node=q->head;
        q->head=q->head->next;
        if(q->head==NULL){
            q->tail=NULL;
        }
        free(temp_node);
    }
}
void printqueue(struct queue *q){
    if(isempty(q)){
        printf("Queue is empty");
    }else{
        struct node *temp_node=q->head;
        while(temp_node!=NULL){
            printf("%lld",temp_node->item);
            temp_node=temp_node->next;
        }
    }
    printf("\n");
}
int main(void) {
    struct queue *work_queue;
    work_queue=create_queue();
    enqueue(work_queue,2);
    enqueue(work_queue,3);
    enqueue(work_queue,1);
    enqueue(work_queue,1);
    printqueue(work_queue);
    dequeue(work_queue);
    dequeue(work_queue);
    printqueue(work_queue);
    dequeue(work_queue);
    dequeue(work_queue);
    printqueue(work_queue);
    return 0;
}

