#ifndef LOG_H
#define LOG_H

typedef struct {
	char timestamp[32];
	char source[32];
	char message[256];
	char level[16];
	int is_alert;
	char reason[64];
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

void check_alert(LogEntry *entry);

#endif