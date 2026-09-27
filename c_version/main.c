#include "mongoose.h"
#include "analyzer.h"
#include "log_generator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *s_listen_on = "http://0.0.0.0:8080";
static const char *s_web_root = "public";

static Analyzer* analyzer = NULL;
static int simulation_speed = 5;

// Array of alerts and logs to send to frontend
static Alert pending_alerts[200];
static int pending_alert_count = 0;
static LogEvent pending_logs[400];
static int pending_log_count = 0;

static void simulation_tick(void *arg) {
    (void)arg;
    printf("[DEBUG] Tick start...\n"); fflush(stdout);
    if (analyzer == NULL) return;

    if (simulation_speed > 0) {
        int gen_count = simulation_speed;
        if (rand() % 100 < 10) gen_count += (rand() % 15) + 5; // burst
        
        LogEvent gen_logs[50];
        int generated = log_generator_generate_batch(gen_count, gen_logs, 50);
        analyzer_ingest(analyzer, gen_logs, generated);
        
        for (int i = 0; i < generated && pending_log_count < 400; i++) {
            pending_logs[pending_log_count++] = gen_logs[i];
        }
    }
    
    // Process queue
    Alert new_alerts[50];
    int alert_count = analyzer_process_queue(analyzer, simulation_speed > 0 ? simulation_speed + 5 : 20, new_alerts, 50);
    
    for (int i = 0; i < alert_count && pending_alert_count < 200; i++) {
        pending_alerts[pending_alert_count++] = new_alerts[i];
    }
}

// Custom JSON Parser for ingested log events
static int parse_json_log_events(const char* body, size_t len, LogEvent* out_events, int max_events) {
    int count = 0;
    const char* ptr = body;
    const char* end = body + len;
    
    while (ptr < end && count < max_events) {
        const char* obj_start = strchr(ptr, '{');
        if (!obj_start || obj_start >= end) break;
        
        const char* obj_end = strchr(obj_start, '}');
        if (!obj_end || obj_end >= end) break;
        
        LogEvent e;
        memset(&e, 0, sizeof(LogEvent));
        e.id = rand() % 100000 + 1;
        e.timestamp = get_time_ms();
        e.port = 80;
        e.severity = 5;
        strcpy(e.ip, "192.168.1.1");
        strcpy(e.action, "DATA_READ");
        strcpy(e.status, "SUCCESS");
        
        // Extract "ip"
        char* ip_p = strstr((char*)obj_start, "\"ip\"");
        if (ip_p && ip_p < obj_end) {
            char* val_s = strchr(ip_p + 4, '"');
            if (val_s && val_s < obj_end) {
                val_s++;
                char* val_e = strchr(val_s, '"');
                if (val_e && val_e <= obj_end) {
                    int l = (int)(val_e - val_s);
                    if (l >= MAX_STR_LEN) l = MAX_STR_LEN - 1;
                    strncpy(e.ip, val_s, l);
                    e.ip[l] = '\0';
                }
            }
        }
        
        // Extract "action"
        char* act_p = strstr((char*)obj_start, "\"action\"");
        if (act_p && act_p < obj_end) {
            char* val_s = strchr(act_p + 8, '"');
            if (val_s && val_s < obj_end) {
                val_s++;
                char* val_e = strchr(val_s, '"');
                if (val_e && val_e <= obj_end) {
                    int l = (int)(val_e - val_s);
                    if (l >= MAX_STR_LEN) l = MAX_STR_LEN - 1;
                    strncpy(e.action, val_s, l);
                    e.action[l] = '\0';
                }
            }
        }
        
        // Extract "status"
        char* st_p = strstr((char*)obj_start, "\"status\"");
        if (st_p && st_p < obj_end) {
            char* val_s = strchr(st_p + 8, '"');
            if (val_s && val_s < obj_end) {
                val_s++;
                char* val_e = strchr(val_s, '"');
                if (val_e && val_e <= obj_end) {
                    int l = (int)(val_e - val_s);
                    if (l >= MAX_STR_LEN) l = MAX_STR_LEN - 1;
                    strncpy(e.status, val_s, l);
                    e.status[l] = '\0';
                }
            }
        }
        
        // Extract "port"
        char* port_p = strstr((char*)obj_start, "\"port\"");
        if (port_p && port_p < obj_end) {
            char* colon = strchr(port_p + 6, ':');
            if (colon && colon < obj_end) {
                e.port = atoi(colon + 1);
            }
        }
        
        // Extract "severity"
        char* sev_p = strstr((char*)obj_start, "\"severity\"");
        if (sev_p && sev_p < obj_end) {
            char* colon = strchr(sev_p + 10, ':');
            if (colon && colon < obj_end) {
                e.severity = atoi(colon + 1);
            }
        }

        out_events[count++] = e;
        ptr = obj_end + 1;
    }
    return count;
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        if (mg_match(hm->uri, mg_str("/api/state"), NULL)) {
            static char buf[32768];
            static char logs_json[16384];
            static char alerts_json[16384];
            
            // Build logs array
            strcpy(logs_json, "[");
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
            strcpy(alerts_json, "[");
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
            
            mg_http_reply(c, 200, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n", buf);
            
            // Clear pending after sending
            pending_log_count = 0;
            pending_alert_count = 0;
            
        } else if (mg_match(hm->uri, mg_str("/api/ingest"), NULL)) {
            // Process custom uploaded/inserted log events
            LogEvent custom_events[200];
            int count = parse_json_log_events(hm->body.buf, hm->body.len, custom_events, 200);
            
            if (count > 0) {
                analyzer_ingest(analyzer, custom_events, count);
                
                // Keep in pending logs for UI display
                for (int i = 0; i < count && pending_log_count < 400; i++) {
                    pending_logs[pending_log_count++] = custom_events[i];
                }
                
                // Immediately process queue
                Alert custom_alerts[50];
                int alert_count = analyzer_process_queue(analyzer, count + 10, custom_alerts, 50);
                
                for (int i = 0; i < alert_count && pending_alert_count < 200; i++) {
                    pending_alerts[pending_alert_count++] = custom_alerts[i];
                }
                
                char resp[256];
                sprintf(resp, "{\"status\":\"ok\",\"ingested\":%d,\"alertsGenerated\":%d}", count, alert_count);
                mg_http_reply(c, 200, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n", resp);
            } else {
                mg_http_reply(c, 400, "Content-Type: application/json\r\n", "{\"status\":\"error\",\"message\":\"No valid logs parsed\"}");
            }

        } else if (mg_match(hm->uri, mg_str("/api/speed"), NULL)) {
            char val[10];
            if (mg_http_get_var(&hm->query, "val", val, sizeof(val)) > 0) {
                simulation_speed = atoi(val);
                if (simulation_speed < 0) simulation_speed = 0;
            }
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"status\":\"ok\"}");
        } else if (mg_match(hm->uri, mg_str("/api/reset"), NULL)) {
            if (analyzer) analyzer_free(analyzer);
            analyzer = analyzer_create();
            pending_log_count = 0;
            pending_alert_count = 0;
            mg_http_reply(c, 200, "Content-Type: application/json\r\n", "{\"status\":\"ok\"}");
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
    
    // Try listening on port 8080, fallback to 5000 if busy
    if (mg_http_listen(&mgr, s_listen_on, fn, NULL) == NULL) {
        s_listen_on = "http://0.0.0.0:5000";
        if (mg_http_listen(&mgr, s_listen_on, fn, NULL) == NULL) {
            s_listen_on = "http://0.0.0.0:3000";
            mg_http_listen(&mgr, s_listen_on, fn, NULL);
        }
    }
    
    printf("==================================================\n");
    printf("  CyberShield-AI C Server Listening on %s  \n", s_listen_on);
    printf("==================================================\n");
    fflush(stdout);
    
    for (;;) {
        mg_mgr_poll(&mgr, 100);
        simulation_tick(NULL);
    }
    
    mg_mgr_free(&mgr);
    analyzer_free(analyzer);
    return 0;
}
