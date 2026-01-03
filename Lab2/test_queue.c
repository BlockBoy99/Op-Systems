#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct node {
  struct node * next;
  long long item;
};

struct queue{ // data structure for queue
    struct node *head;
    struct node *tail;
    pthread_mutex_t lock;          // make thread safe
    pthread_cond_t cond;    
}; queue;
struct queue *queue_create(void){ //create a qeue and return pointer
    struct queue *q= (struct queue *) malloc(sizeof(struct queue));
    q->head=NULL;
    q->tail=NULL;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    return(q);
}
void queue_destroy(queue *q){
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
    free(q);
}





int isempty(struct queue *q){
    if(q->head==NULL){
        return(1);
    }
    return(0);
}
void queue_push(struct queue *q, void* item){

    if(!q || item) return;
    struct node *new_node=(struct node*) malloc(sizeof(struct node));
    new_node-> item=item;
    new_node->next=NULL;
    pthread_mutex_lock(&q->lock);
    if(q->tail){
        q->tail->next=new_node;
        q->tail=new_node;
    } else{
        q->head=new_node;
        q->tail=new_node;
    }
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

void *queue_pop(struct queue *q){
    if(!q) return NULL;
    pthread_mutex_lock(&q->lock);
    while (q->head==NULL)
    {
        pthread_cond_wait(&q->cond, &q->lock);
    }
   
    struct node *temp_node=q->head;
    long long item=temp_node->item;
    q->head=q->head->next;
    if(q->head==NULL){
        q->tail=NULL;
    }
    free(temp_node);
    pthread_mutex_unlock(&q->lock);
    return item;
}


