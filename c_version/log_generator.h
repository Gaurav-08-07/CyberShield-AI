#ifndef LOG_GENERATOR_H
#define LOG_GENERATOR_H

#include "data_structures.h"

// Initialize the random seed and state
void log_generator_init();

// Generate a batch of logs, returning the number generated
int log_generator_generate_batch(int count, LogEvent* out_events, int max_events);

#endif // LOG_GENERATOR_H
