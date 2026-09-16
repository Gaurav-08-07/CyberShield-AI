#include "log_generator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static uint64_t get_time_ms() {
    return GetTickCount64();
}
#else
#include <sys/time.h>
static uint64_t get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}
#endif

static int event_id = 0;
static int attack_cooldown = 0;

static LogEvent attack_scenarios[100];
static int attack_scenario_count = 0;

const char* IPS[] = {"192.168.1.10", "10.0.0.5", "172.16.0.50", "45.33.22.11", "104.22.3.44", "8.8.8.8"};
const char* ACTIONS[] = {"LOGIN_ATTEMPT", "DATA_READ", "FILE_UPLOAD", "PORT_SCAN", "PRIVILEGE_ESCALATION", "DATA_EXPORT"};
const int PORTS[] = {22, 80, 443, 3306, 8080};
const char* STATUSES[] = {"SUCCESS", "FAILED", "BLOCKED"};

void log_generator_init() {
    srand((unsigned int)time(NULL));
    attack_cooldown = 10;
}

static LogEvent create_event(const char* type) {
    LogEvent e;
    e.id = ++event_id;
    e.timestamp = get_time_ms();
    
    strcpy(e.ip, IPS[rand() % 6]);
    strcpy(e.action, type);
    e.port = PORTS[rand() % 5];
    strcpy(e.status, "SUCCESS");
    e.severity = rand() % 10 + 1; // 1-10
    
    if (strcmp(type, "LOGIN_ATTEMPT") == 0) {
        if (rand() % 100 < 30) strcpy(e.status, "FAILED");
        e.port = 22;
        e.severity = 3;
    } else if (strcmp(type, "PORT_SCAN") == 0) {
        strcpy(e.status, "BLOCKED");
        e.severity = 6;
    }
    
    return e;
}

static void inject_attack_scenario() {
    int scenario = rand() % 5;
    attack_scenario_count = 0; // Clear old
    
    if (scenario == 0) {
        // Brute force
        for (int i=0; i<15; i++) {
            LogEvent e = create_event("LOGIN_ATTEMPT");
            strcpy(e.ip, "45.33.22.11");
            strcpy(e.status, "FAILED");
            e.severity = 5;
            attack_scenarios[attack_scenario_count++] = e;
        }
    } else if (scenario == 1) {
        // Port scan
        for (int i=0; i<10; i++) {
            LogEvent e = create_event("PORT_SCAN");
            strcpy(e.ip, "104.22.3.44");
            e.port = i * 100;
            e.severity = 4;
            attack_scenarios[attack_scenario_count++] = e;
        }
    } else if (scenario == 2) {
        // DDoS
        for (int i=0; i<30; i++) {
            LogEvent e = create_event("DATA_READ");
            strcpy(e.ip, "8.8.8.8");
            e.port = 80;
            e.severity = 2;
            attack_scenarios[attack_scenario_count++] = e;
        }
    } else if (scenario == 3) {
        // Privilege escalation
        LogEvent e1 = create_event("LOGIN_ATTEMPT");
        strcpy(e1.ip, "10.0.0.5"); strcpy(e1.status, "SUCCESS"); e1.severity = 2;
        
        LogEvent e2 = create_event("PRIVILEGE_ESCALATION");
        strcpy(e2.ip, "10.0.0.5"); strcpy(e2.status, "SUCCESS"); e2.severity = 9;
        
        attack_scenarios[attack_scenario_count++] = e1;
        attack_scenarios[attack_scenario_count++] = e2;
    } else if (scenario == 4) {
        // Data exfil
        LogEvent e = create_event("DATA_EXPORT");
        strcpy(e.ip, "172.16.0.50");
        e.severity = 8;
        attack_scenarios[attack_scenario_count++] = e;
    }
}

int log_generator_generate_batch(int count, LogEvent* out_events, int max_events) {
    int generated = 0;
    
    attack_cooldown--;
    if (attack_cooldown <= 0 && (rand() % 100 < 15)) {
        inject_attack_scenario();
        attack_cooldown = (rand() % 20) + 10;
    }
    
    // Flush queued backwards because we push them to an array, but order doesn't strictly matter
    while (attack_scenario_count > 0 && generated < max_events) {
        out_events[generated] = attack_scenarios[--attack_scenario_count];
        out_events[generated].id = ++event_id;
        out_events[generated].timestamp = get_time_ms();
        generated++;
    }
    
    for (int i=0; i<count && generated < max_events; i++) {
        // Weighted random
        int r = rand() % 100;
        const char* type = "DATA_READ";
        if (r < 50) type = "DATA_READ";
        else if (r < 80) type = "LOGIN_ATTEMPT";
        else if (r < 90) type = "FILE_UPLOAD";
        else type = "PORT_SCAN";
        
        out_events[generated++] = create_event(type);
    }
    
    return generated;
}
