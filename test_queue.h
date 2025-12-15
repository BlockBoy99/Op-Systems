#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>

// Node container for queue items
typedef struct queue_node {
    void *data;
    struct queue_node *next;
} queue_node;

// Queue structure
typedef struct queue {
    queue_node *head;
    queue_node *tail;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} queue;

// Create a new empty queue
queue *queue_create(void);

// Destroy queue (caller must ensure it is empty first)
void queue_destroy(queue *q);

// Push item to tail (producer)
void queue_push(queue *q, void *item);

// Pop item from head (consumer) — BLOCKS if empty
void *queue_pop(queue *q);

#endif