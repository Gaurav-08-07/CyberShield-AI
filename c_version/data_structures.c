#include "data_structures.h"
#include <stdio.h>

// --- Queue ---
Queue* queue_create() {
    Queue* q = (Queue*)malloc(sizeof(Queue));
    q->head = 0;
    q->tail = 0;
    q->size = 0;
    q->capacity = QUEUE_CAPACITY;
    q->total_in = 0;
    return q;
}

bool queue_enqueue(Queue* q, LogEvent event) {
    if (q->size == q->capacity) {
        // Overwrite oldest element (circular buffer behavior)
        q->head = (q->head + 1) % q->capacity;
        q->size--;
    }
    q->buffer[q->tail] = event;
    q->tail = (q->tail + 1) % q->capacity;
    q->size++;
    q->total_in++;
    return true;
}

bool queue_dequeue(Queue* q, LogEvent* out_event) {
    if (q->size == 0) return false;
    *out_event = q->buffer[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->size--;
    return true;
}

bool queue_is_empty(Queue* q) {
    return q->size == 0;
}

void queue_free(Queue* q) {
    free(q);
}

// --- Hash Table ---
unsigned int hash(const char* key) {
    unsigned int hash = 5381;
    int c;
    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash % HASH_TABLE_SIZE;
}

HashTable* hash_table_create() {
    HashTable* ht = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        ht->buckets[i] = NULL;
    }
    return ht;
}

void hash_table_insert(HashTable* ht, const char* key) {
    unsigned int h = hash(key);
    HashNode* node = ht->buckets[h];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            node->count++;
            return;
        }
        node = node->next;
    }
    // Not found, insert new
    HashNode* new_node = (HashNode*)malloc(sizeof(HashNode));
    strncpy(new_node->key, key, MAX_STR_LEN - 1);
    new_node->key[MAX_STR_LEN - 1] = '\0';
    new_node->count = 1;
    new_node->next = ht->buckets[h];
    ht->buckets[h] = new_node;
}

int hash_table_get(HashTable* ht, const char* key) {
    unsigned int h = hash(key);
    HashNode* node = ht->buckets[h];
    while (node) {
        if (strcmp(node->key, key) == 0) {
            return node->count;
        }
        node = node->next;
    }
    return 0;
}

void hash_table_free(HashTable* ht) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashNode* node = ht->buckets[i];
        while (node) {
            HashNode* temp = node;
            node = node->next;
            free(temp);
        }
    }
    free(ht);
}

// --- BST (AVL) ---
int bst_height(BSTNode* N) {
    if (N == NULL) return 0;
    return N->height;
}

int max(int a, int b) {
    return (a > b) ? a : b;
}

BSTNode* bst_new_node(LogEvent event) {
    BSTNode* node = (BSTNode*)malloc(sizeof(BSTNode));
    node->event = event;
    node->left = NULL;
    node->right = NULL;
    node->height = 1;
    return node;
}

BSTNode* bst_right_rotate(BSTNode* y) {
    if (y == NULL || y->left == NULL) return y;
    BSTNode* x = y->left;
    BSTNode* T2 = x->right;
    x->right = y;
    y->left = T2;
    y->height = max(bst_height(y->left), bst_height(y->right)) + 1;
    x->height = max(bst_height(x->left), bst_height(x->right)) + 1;
    return x;
}

BSTNode* bst_left_rotate(BSTNode* x) {
    if (x == NULL || x->right == NULL) return x;
    BSTNode* y = x->right;
    BSTNode* T2 = y->left;
    y->left = x;
    x->right = T2;
    x->height = max(bst_height(x->left), bst_height(x->right)) + 1;
    y->height = max(bst_height(y->left), bst_height(y->right)) + 1;
    return y;
}

int bst_get_balance(BSTNode* N) {
    if (N == NULL) return 0;
    return bst_height(N->left) - bst_height(N->right);
}

BSTNode* bst_insert_node(BSTNode* node, LogEvent event) {
    if (node == NULL) return bst_new_node(event);

    if (event.severity < node->event.severity)
        node->left = bst_insert_node(node->left, event);
    else if (event.severity > node->event.severity)
        node->right = bst_insert_node(node->right, event);
    else {
        // Equal severities. Add to left or right arbitrarily. Let's say right.
        node->right = bst_insert_node(node->right, event);
    }

    node->height = 1 + max(bst_height(node->left), bst_height(node->right));
    int balance = bst_get_balance(node);

    if (balance > 1 && node->left && event.severity < node->left->event.severity)
        return bst_right_rotate(node);
    if (balance < -1 && node->right && event.severity > node->right->event.severity)
        return bst_left_rotate(node);
    if (balance > 1 && node->left && event.severity >= node->left->event.severity) {
        node->left = bst_left_rotate(node->left);
        return bst_right_rotate(node);
    }
    if (balance < -1 && node->right && event.severity <= node->right->event.severity) {
        node->right = bst_right_rotate(node->right);
        return bst_left_rotate(node);
    }
    return node;
}

BST* bst_create() {
    BST* bst = (BST*)malloc(sizeof(BST));
    bst->root = NULL;
    return bst;
}

void bst_insert(BST* bst, LogEvent event) {
    bst->root = bst_insert_node(bst->root, event);
}

void bst_range_query(BSTNode* node, int min_severity, int max_severity, LogEvent* results, int* count, int max_results) {
    if (node == NULL || *count >= max_results) return;

    if (min_severity < node->event.severity) {
        bst_range_query(node->left, min_severity, max_severity, results, count, max_results);
    }

    if (min_severity <= node->event.severity && max_severity >= node->event.severity) {
        if (*count < max_results) {
            results[*count] = node->event;
            (*count)++;
        }
    }

    if (max_severity > node->event.severity) {
        bst_range_query(node->right, min_severity, max_severity, results, count, max_results);
    }
}

void bst_free_nodes(BSTNode* node) {
    if (node) {
        bst_free_nodes(node->left);
        bst_free_nodes(node->right);
        free(node);
    }
}

void bst_free(BST* bst) {
    bst_free_nodes(bst->root);
    free(bst);
}

// --- Stack ---
Stack* stack_create() {
    Stack* s = (Stack*)malloc(sizeof(Stack));
    s->top = -1;
    return s;
}

bool stack_push(Stack* s, LogEvent event) {
    if (s->top >= STACK_CAPACITY - 1) {
        s->top = STACK_CAPACITY / 2;
    }
    s->buffer[++(s->top)] = event;
    return true;
}

bool stack_pop(Stack* s, LogEvent* out_event) {
    if (s->top < 0) return false;
    *out_event = s->buffer[(s->top)--];
    return true;
}

bool stack_peek(Stack* s, LogEvent* out_event) {
    if (s->top < 0) return false;
    *out_event = s->buffer[s->top];
    return true;
}

void stack_clear(Stack* s) {
    s->top = -1;
}

void stack_free(Stack* s) {
    free(s);
}
