#ifndef QUEUE_H
#define QUEUE_H

struct node {
    long long item;
    struct node *next;
};

struct queue {
    struct node *head;
    struct node *tail;
};

struct queue *create_queue(void);
int isempty(struct queue *q);
void enqueue(struct queue *q, long long item);
void dequeue(struct queue *q);

long long dequeue_with_item(struct queue *q);

#endif