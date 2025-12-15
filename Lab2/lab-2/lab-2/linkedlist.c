#include <stdio.h>
#include <stdlib.h>

struct element {
  struct element * next;
  int data; 
};

struct linked_list {
  struct element * head;
};


int remove_head(struct linked_list * list) {
  struct element * elem = list->head;
  if (elem) {
    int result = elem->data;
    list->head = elem->next;
    free(elem);
    return result;
  } else {
    return 0;
  }
}

void prepend_int(struct linked_list * list, int val) {
  struct element * elem = malloc(sizeof(struct element));
  elem->data = val;
  elem->next = list->head;
  list->head = elem;
}

void append_int(struct linked_list * list, int val) {
  // Create a new element to append to our list
  struct element * elem = malloc(sizeof(struct element));
  elem->data = val;
  elem->next = NULL;
  if (list->head == NULL) {
    // Empty list, we need to set the head to be our element
    list->head = elem;
  } else {
    // List already contains some items, so add ours to the last one
    struct element * tail = list->head;
    while (tail->next != NULL) {
    // Keep going down the list until next is null, meaning we are at the end.
      tail = tail->next;
    }
    tail->next = elem;
  }
}




int main(void) {
  struct linked_list * list = malloc(sizeof(struct linked_list));
  list->head = NULL;
  append_int(list, 4);
  append_int(list, 5);
  append_int(list, 6);
  prepend_int(list, 3);
  prepend_int(list, 2);
  prepend_int(list, 1);
  // Print the items in our list
  int item;
  struct element * cursor;
  for (item = 0, cursor = list->head; cursor != NULL; cursor = cursor->next) {
    printf("Item %d: %d\n", item++, cursor->data);
  }
  // Drain list
  while (list->head) {
    printf("Removed %d\n", remove_head(list));
  }
  return EXIT_SUCCESS;
}
