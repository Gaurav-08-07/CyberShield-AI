#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STR_LEN 32
#define QUEUE_CAPACITY 500
#define HASH_TABLE_SIZE 1024
#define STACK_CAPACITY 100
#define MAX_ALERTS 1024

// Log Event
typedef struct {
    int id;
    char ip[MAX_STR_LEN];
    char action[MAX_STR_LEN];
    int port;
    char status[MAX_STR_LEN];
    int severity;
    uint64_t timestamp;
} LogEvent;

// Alert
typedef struct {
    char type[64];
    char message[256];
    int severity;
    char details[256];
    uint64_t timestamp;
} Alert;

// --- Queue (Circular Buffer) ---
typedef struct {
    LogEvent buffer[QUEUE_CAPACITY];
    int head;
    int tail;
    int size;
    int capacity;
    int total_in;
} Queue;

Queue* queue_create();
bool queue_enqueue(Queue* q, LogEvent event);
bool queue_dequeue(Queue* q, LogEvent* out_event);
bool queue_is_empty(Queue* q);
int queue_get_items(Queue* q, LogEvent* out_events, int max_items);
void queue_free(Queue* q);

// --- Hash Table (Chaining) ---
typedef struct HashNode {
    char key[MAX_STR_LEN];
    int count;
    struct HashNode* next;
} HashNode;

typedef struct {
    HashNode* buckets[HASH_TABLE_SIZE];
} HashTable;

HashTable* hash_table_create();
void hash_table_insert(HashTable* ht, const char* key);
int hash_table_get(HashTable* ht, const char* key);
int hash_table_get_top(HashTable* ht, char out_keys[][MAX_STR_LEN], int out_counts[], int max_items);
void hash_table_free(HashTable* ht);

// --- BST (AVL Tree) ---
typedef struct BSTNode {
    LogEvent event;
    int height;
    struct BSTNode* left;
    struct BSTNode* right;
} BSTNode;

typedef struct {
    BSTNode* root;
} BST;

BST* bst_create();
void bst_insert(BST* bst, LogEvent event);
void bst_range_query(BSTNode* node, int min_severity, int max_severity, LogEvent* results, int* count, int max_results);
void bst_free(BST* bst);

// --- Stack ---
typedef struct {
    LogEvent buffer[STACK_CAPACITY];
    int top;
} Stack;

Stack* stack_create();
bool stack_push(Stack* s, LogEvent event);
bool stack_pop(Stack* s, LogEvent* out_event);
bool stack_peek(Stack* s, LogEvent* out_event);
int stack_get_items(Stack* s, LogEvent* out_events, int max_items);
void stack_clear(Stack* s);
void stack_free(Stack* s);

#endif // DATA_STRUCTURES_H
