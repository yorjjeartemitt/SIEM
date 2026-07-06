#include "log.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
void log_buffer_init(LogBuffer *buf,int initial_capacity){
    buf->data=malloc(sizeof(LogEntry)*initial_capacity);
    buf->count=0;
    buf->capacity=initial_capacity;
}
void log_buffer_push(LogBuffer *buf,LogEntry entry){
    if (buf->count>=buf->capacity){
        buf->capacity*=2;
        buf->data=realloc(buf->data,sizeof(LogEntry)*buf->capacity);
    }
    buf->data[buf->count]=entry;
    buf->count++;
}
void log_buffer_free(LogBuffer *buf){
    free(buf->data);
    buf->data=NULL;
    buf->count=0;
    buf->capacity=0;
}
void check_alert(LogEntry *entry){
    char lower_msg[256];
    int i;
    for (i=0;entry->message[i] && i<255;i++){
        lower_msg[i]=tolower((unsigned char)entry->message[i]);
    }
    lower_msg[i]=0;
    if (strstr(lower_msg,"error")){
        entry->is_alert=1;
        strncpy(entry->reason,"keyword: error",sizeof(entry->reason));
        return;
    }
    if (strstr(lower_msg,"faild")){
        entry->is_alert=1;
        strncpy(entry->reason,"keyword: failed",sizeof(entry->reason));
        return;
    }
    if (strstr(lower_msg,"denied")){
        entry->is_alert=1;
        strncpy(entry->reason,"keyword: denied",sizeof(entry->reason));
        return;
    }
    if (strstr(lower_msg,"warning")){
        entry->is_alert=1;
        strncpy(entry->reason,"keyword: warning",sizeof(entry->reason));
        return;
    }

    entry->is_alert=0;
    entry->reason[0]=0;
}
int parse_pacman_log(const char *filepath,LogBuffer *buf){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    char line[512];
    while (fgets(line,sizeof(line),f)){
        char timestamp[32],source[32],message[256];
        char *p1=strchr(line,'[');
        if (!p1) continue;
        char *p2=strchr(p1+1,']');
        if (!p2) continue;
        char *p3=strchr(p2+1,'[');
        if (!p3) continue;
        char *p4=strchr(p3+1,']');
        if (!p4) continue;

        int ts_len=p2-p1-1;
        snprintf(timestamp,sizeof(timestamp),"%.*s",ts_len,p1+1);
        int src_len=p4-p3-1;
        snprintf(source,sizeof(source),"%.*s",src_len,p3+1);
        snprintf(message,sizeof(message),"%s",p4+2);
        message[strcspn(message,"\n")]=0;
        
        LogEntry entry;
        strncpy(entry.timestamp,timestamp,sizeof(entry.timestamp));
        strncpy(entry.source,source,sizeof(entry.source));
        strncpy(entry.message,message,sizeof(entry.message));
        check_alert(&entry);
        log_buffer_push(buf,entry);
    }
    fclose(f);
    return buf->count;
}