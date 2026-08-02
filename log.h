#ifndef LOG_H
#define LOG_H
#include <stddef.h>
typedef struct {
	char timestamp[32];
	char timestamp_sec[32];
	char source[32];
	char message[256];
	char level[16];
	int is_alert;
	char reason[64];
	char severity[16];
	char category[32];
	char verdict[8];
} LogEntry;

typedef struct {
    LogEntry *data;
    int count;
    int capacity;
} LogBuffer;

void log_buffer_init(LogBuffer *buf,int initial_capacity);
void log_buffer_push(LogBuffer *buf,LogEntry entry);
void log_buffer_free(LogBuffer *buf);

int parse_generic_log(const char *filepath,LogBuffer *buf);
int parse_pacman_log(const char *filepath,LogBuffer *buf);
int parse_auth_log(const char *filepath,LogBuffer *buf);
int parse_jornalctl_live(LogBuffer *buf,int max_lines);
int parse_journalctl_incremental(LogBuffer *buf, char *last_timestamp, size_t ts_size,char *last_line,size_t line_size);
int parse_auth_log_incremental(const char *filepath,LogBuffer *buf,long *offset);
int parse_pacman_log_incremental(const char *filepath,LogBuffer *buf,long *offset);
int parser_conf_rules(const char *filepath);
void check_alert(LogEntry *entry);

#endif