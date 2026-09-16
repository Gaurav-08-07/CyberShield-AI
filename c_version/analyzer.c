#include "analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Analyzer* analyzer_create() {
    Analyzer* a = (Analyzer*)malloc(sizeof(Analyzer));
    a->queue = queue_create();
    a->ip_freq = hash_table_create();
    a->port_freq = hash_table_create();
    a->severity_tree = bst_create();
    a->event_stack = stack_create();
    a->processed_count = 0;
    a->threat_count = 0;
    return a;
}

void analyzer_ingest(Analyzer* a, LogEvent* events, int count) {
    for (int i = 0; i < count; i++) {
        queue_enqueue(a->queue, events[i]);
    }
}

// Global buffer for recent alerts to prevent spam (deduplication)
static char recent_alert_keys[MAX_ALERTS][128];
static int recent_alert_count = 0;

static bool is_duplicate_alert(const char* key) {
    for (int i = 0; i < recent_alert_count; i++) {
        if (strcmp(recent_alert_keys[i], key) == 0) return true;
    }
    if (recent_alert_count < MAX_ALERTS) {
        strcpy(recent_alert_keys[recent_alert_count++], key);
    }
    return false;
}

int analyzer_process_queue(Analyzer* a, int limit, Alert* out_alerts, int max_alerts) {
    int alert_count = 0;
    int processed = 0;
    LogEvent event;
    
    // Clear recent alerts occasionally (naive sliding window)
    if (a->processed_count % 1000 == 0) recent_alert_count = 0;

    while (processed < limit && queue_dequeue(a->queue, &event)) {
        processed++;
        a->processed_count++;
        
        // Update indices
        hash_table_insert(a->ip_freq, event.ip);
        
        char port_str[32];
        sprintf(port_str, "%d", event.port);
        hash_table_insert(a->port_freq, port_str);
        
        bst_insert(a->severity_tree, event);
        stack_push(a->event_stack, event);
        
        int ip_count = hash_table_get(a->ip_freq, event.ip);
        int port_count = hash_table_get(a->port_freq, port_str);
        
        // 1. Brute Force (Hash Table)
        if (ip_count > 15 && strcmp(event.status, "FAILED") == 0 && strcmp(event.action, "LOGIN_ATTEMPT") == 0) {
            char key[128]; sprintf(key, "BRUTE_%s", event.ip);
            if (!is_duplicate_alert(key) && alert_count < max_alerts) {
                Alert al = {"Brute Force", "Multiple failed logins", 8, "", event.timestamp};
                sprintf(al.details, "IP: %s (%d attempts)", event.ip, ip_count);
                out_alerts[alert_count++] = al;
                a->threat_count++;
            }
        }
        
        // 2. DDoS (Hash Table)
        if (port_count > 30 && strcmp(event.action, "DATA_READ") == 0) {
            char key[128]; sprintf(key, "DDOS_%d", event.port);
            if (!is_duplicate_alert(key) && alert_count < max_alerts) {
                Alert al = {"DDoS Attack", "High traffic volume", 9, "", event.timestamp};
                sprintf(al.details, "Port: %d (%d requests)", event.port, port_count);
                out_alerts[alert_count++] = al;
                a->threat_count++;
            }
        }
        
        // 3. Privilege Escalation (Stack)
        LogEvent top1, top2;
        if (stack_peek(a->event_stack, &top1) && strcmp(top1.action, "PRIVILEGE_ESCALATION") == 0) {
            stack_pop(a->event_stack, &top1); // remove top1
            if (stack_peek(a->event_stack, &top2) && strcmp(top2.action, "LOGIN_ATTEMPT") == 0 && strcmp(top1.ip, top2.ip) == 0) {
                char key[128]; sprintf(key, "PRIVESC_%s", event.ip);
                if (!is_duplicate_alert(key) && alert_count < max_alerts) {
                    Alert al = {"Privilege Escalation", "Login followed by escalation", 10, "", event.timestamp};
                    sprintf(al.details, "IP: %s", event.ip);
                    out_alerts[alert_count++] = al;
                    a->threat_count++;
                }
            }
            stack_push(a->event_stack, top1); // restore
        }
        
        // 4. Port Scan
        if (strcmp(event.action, "PORT_SCAN") == 0) {
            char key[128]; sprintf(key, "PORTSCAN_%s", event.ip);
            if (!is_duplicate_alert(key) && alert_count < max_alerts) {
                Alert al = {"Port Scan", "Sequential port probing detected", 6, "", event.timestamp};
                sprintf(al.details, "IP: %s scanned port %d", event.ip, event.port);
                out_alerts[alert_count++] = al;
                a->threat_count++;
            }
        }
        
        // 5. Data Exfiltration
        if (strcmp(event.action, "DATA_EXPORT") == 0) {
            char key[128]; sprintf(key, "EXFIL_%s", event.ip);
            if (!is_duplicate_alert(key) && alert_count < max_alerts) {
                Alert al = {"Data Exfiltration", "Unauthorized data transfer", 10, "", event.timestamp};
                sprintf(al.details, "IP: %s", event.ip);
                out_alerts[alert_count++] = al;
                a->threat_count++;
            }
        }
    }
    
    // 6. High Severity Spike (BST Range Query)
    LogEvent high_sev_results[50];
    int high_sev_count = 0;
    bst_range_query(a->severity_tree->root, 8, 10, high_sev_results, &high_sev_count, 50);
    if (high_sev_count > 10) {
        if (!is_duplicate_alert("SEV_SPIKE") && alert_count < max_alerts) {
            Alert al = {"Severity Spike", "Abnormal number of critical events", 9, "", get_time_ms()};
            sprintf(al.details, "%d high severity events detected in tree", high_sev_count);
            out_alerts[alert_count++] = al;
            a->threat_count++;
        }
    }
    
    return alert_count;
}

void analyzer_free(Analyzer* a) {
    queue_free(a->queue);
    hash_table_free(a->ip_freq);
    hash_table_free(a->port_freq);
    bst_free(a->severity_tree);
    stack_free(a->event_stack);
    free(a);
}
