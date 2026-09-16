#include "mongoose.h"
#include "analyzer.h"
#include "log_generator.h"
#include <stdio.h>
#include <stdlib.h>

static const char *s_listen_on = "http://localhost:8080";
static const char *s_web_root = "public";

static Analyzer* analyzer = NULL;
static int simulation_speed = 5;

// Array of alerts to send to frontend
static Alert pending_alerts[100];
static int pending_alert_count = 0;
static LogEvent pending_logs[200];
static int pending_log_count = 0;

static void simulation_tick(void *arg) {
    (void)arg;
    if (analyzer == NULL) return;

    // Generate & Ingest
    int gen_count = simulation_speed;
    if (rand() % 100 < 10) gen_count += (rand() % 15) + 5; // burst
    
    pending_log_count = log_generator_generate_batch(gen_count, pending_logs, 200);
    analyzer_ingest(analyzer, pending_logs, pending_log_count);
    
    // Process
    Alert new_alerts[50];
    int alert_count = analyzer_process_queue(analyzer, simulation_speed + 3, new_alerts, 50);
    
    // Accumulate alerts for the next API poll
    for(int i=0; i<alert_count && pending_alert_count < 100; i++) {
        pending_alerts[pending_alert_count++] = new_alerts[i];
    }
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        if (mg_match(hm->uri, mg_str("/api/state"), NULL)) {
            // Send JSON state
            char buf[8192];
            
            // Build logs array
            char logs_json[4096] = "[";
            for(int i=0; i<pending_log_count; i++) {
                char item[256];
                sprintf(item, "{\"id\":%d,\"ip\":\"%s\",\"action\":\"%s\",\"port\":%d,\"status\":\"%s\",\"severity\":%d,\"timestamp\":%llu}%s",
                    pending_logs[i].id, pending_logs[i].ip, pending_logs[i].action, pending_logs[i].port, 
                    pending_logs[i].status, pending_logs[i].severity, (unsigned long long)pending_logs[i].timestamp,
                    (i == pending_log_count - 1) ? "" : ",");
                strcat(logs_json, item);
            }
            strcat(logs_json, "]");
            
            // Build alerts array
            char alerts_json[4096] = "[";
            for(int i=0; i<pending_alert_count; i++) {
                char item[256];
                sprintf(item, "{\"type\":\"%s\",\"message\":\"%s\",\"severity\":%d,\"details\":\"%s\",\"timestamp\":%llu}%s",
                    pending_alerts[i].type, pending_alerts[i].message, pending_alerts[i].severity, 
                    pending_alerts[i].details, (unsigned long long)pending_alerts[i].timestamp,
                    (i == pending_alert_count - 1) ? "" : ",");
                strcat(alerts_json, item);
            }
            strcat(alerts_json, "]");
            
            sprintf(buf, "{\"stats\":{\"processed\":%d,\"threats\":%d,\"queueSize\":%d,\"queueTotal\":%d},\"logs\":%s,\"alerts\":%s}",
                analyzer->processed_count, analyzer->threat_count, analyzer->queue->size, analyzer->queue->total_in,
                logs_json, alerts_json);
            
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", buf);
            
            // Clear pending after sending
            pending_log_count = 0;
            pending_alert_count = 0;
            
        } else if (mg_match(hm->uri, mg_str("/api/speed"), NULL)) {
            char val[10];
            if (mg_http_get_var(&hm->query, "val", val, sizeof(val)) > 0) {
                simulation_speed = atoi(val);
                if (simulation_speed < 1) simulation_speed = 1;
            }
            mg_http_reply(c, 200, "", "{\"status\":\"ok\"}");
        } else {
            struct mg_http_serve_opts opts = {.root_dir = s_web_root};
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

int main(void) {
    log_generator_init();
    analyzer = analyzer_create();

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, s_listen_on, fn, NULL);
    
    // Run simulation tick every 500ms
    mg_timer_add(&mgr, 500, MG_TIMER_REPEAT, simulation_tick, NULL);

    printf("Starting CyberShield C Server on %s\n", s_listen_on);
    for (;;) {
        mg_mgr_poll(&mgr, 100);
    }
    mg_mgr_free(&mgr);
    analyzer_free(analyzer);
    return 0;
}
