#ifndef ANALYZER_H
#define ANALYZER_H

#include "data_structures.h"

typedef struct {
    Queue* queue;
    HashTable* ip_freq;
    HashTable* port_freq;
    BST* severity_tree;
    Stack* event_stack;
    int processed_count;
    int threat_count;
} Analyzer;

Analyzer* analyzer_create();
void analyzer_ingest(Analyzer* a, LogEvent* events, int count);
int analyzer_process_queue(Analyzer* a, int limit, Alert* out_alerts, int max_alerts);
void analyzer_free(Analyzer* a);

#endif // ANALYZER_H
