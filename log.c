#include "log.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
static int is_level(const char *s){
    return !strcmp(s,"INFO") || !strcmp(s,"WARNING") || !strcmp(s,"WARN") || !strcmp(s,"ERROR") || !strcmp(s,"DEBUG") || !strcmp(s,"CRITICAL");
}
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
    if (!strcmp(entry->level,"ERROR") || !strcmp(entry->level,"CRITICAL")){
        entry->is_alert=1;
        snprintf(entry->reason,sizeof(entry->reason),"level: %s",entry->level);
        return;
    }
    if (!strcmp(entry->level,"WARNING") || !strcmp(entry->level,"WARN")){
        entry->is_alert=1;
        snprintf(entry->reason,sizeof(entry->reason),"level: %s",entry->level);
        return;
    }

    char lower_msg[256];
    int i;
    for (i=0;entry->message[i] && i<255;i++){
        lower_msg[i]=tolower((unsigned char)entry->message[i]);
    }
    lower_msg[i]=0;
    if (strstr(lower_msg,"error")){entry->is_alert=1; strncpy(entry->reason,"keyword: error",sizeof(entry->reason)); return;}
    if (strstr(lower_msg,"failed")){entry->is_alert=1; strncpy(entry->reason,"keyword: failed",sizeof(entry->reason)); return;}
    if (strstr(lower_msg,"denied")){entry->is_alert=1; strncpy(entry->reason,"keyword: denied",sizeof(entry->reason)); return;}
    if (strstr(lower_msg,"warning")){entry->is_alert=1; strncpy(entry->reason,"keyword: warning",sizeof(entry->reason)); return;}

    entry->is_alert=0;
    entry->reason[0]=0;
}
int parse_generic_log(const char *filepath,LogBuffer *buf){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    char line[1024];
    while (fgets(line,sizeof(line),f)){
        line[strcspn(line,"\n")]=0;
        LogEntry entry;
        memset(&entry,0,sizeof(entry));
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s","-");
        snprintf(entry.source,sizeof(entry.source),"%s","custom");
        char date[11],time_[9],level[16];
        if (sscanf(line,"%10s %8s %15s",date,time_,level)==3 && is_level(level)){
            snprintf(entry.timestamp,sizeof(entry.timestamp),"%s %s",date,time_);
            snprintf(entry.level,sizeof(entry.level),"%s",level);
            char *lb=strchr(line,'[');
            char *rb=strchr(line,']');
            if (lb && rb && rb>lb){
                size_t len=rb-lb-1;
                if (len>=sizeof(entry.source)) len=sizeof(entry.source)-1;
                strncpy(entry.source,lb+1,len);
                entry.source[len]=0;
                while (*(rb+1)==' ') rb++;
                strncpy(entry.message,rb+1,sizeof(entry.message)-1);
            }else{
                strncpy(entry.message,line,sizeof(entry.message)-1);
            }
        }else{
            strncpy(entry.message,line,sizeof(entry.message)-1);
        }
        check_alert(&entry);
        log_buffer_push(buf,entry);

    }
    fclose(f);
    return buf->count;
}
int parse_pacman_log(const char *filepath,LogBuffer *buf){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    char line[512];
    while (fgets(line,sizeof(line),f)){
        char *p1=strchr(line,'[');
        if (!p1) continue;
        char *p2=strchr(p1+1,']');
        if (!p2) continue;
        char *p3=strchr(p2+1,'[');
        if (!p3) continue;
        char *p4=strchr(p3+1,']');
        if (!p4) continue;
        LogEntry entry;
        memset(&entry,0,sizeof(entry));

        int ts_len=p2-p1-1;
        if (ts_len<0) continue;
        if ((size_t)ts_len>=sizeof(entry.timestamp)) ts_len=sizeof(entry.timestamp)-1;
        memcpy(entry.timestamp,p1+1,ts_len);
        entry.timestamp[ts_len]=0;
        int src_len=p4-p3-1;
        if (src_len<0) continue;
        if ((size_t)src_len>=sizeof(entry.source)) src_len=sizeof(entry.source)-1;
        memcpy(entry.source,p3+1,src_len);
        entry.source[src_len]=0;
        if ((size_t)(p4-line)+2>strlen(line)) continue;
        char *msg_start=p4+2;
        snprintf(entry.message,sizeof(entry.message),"%s",msg_start);
        entry.message[strcspn(entry.message,"\n")]=0;
        check_alert(&entry);
        log_buffer_push(buf,entry);
    }
    fclose(f);
    return buf->count;
}
int parse_auth_log(const char *filepath,LogBuffer *buf){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    char line[512];
    while (fgets(line,sizeof(line),f)){
        if (strlen(line)<16) continue;
        LogEntry entry;
        memset(&entry,0,sizeof(entry));
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%.15s",line);
        char *p=line+16;
        char *space=strchr(p,' ');
        if (!space) continue;
        int host_len=space-p;
        if (host_len>=(int)sizeof(entry.source)) host_len=sizeof(entry.source)-1;
        memcpy(entry.source,p,host_len);
        entry.source[host_len]=0;
        char *msg_start=space+1;
        snprintf(entry.message,sizeof(entry.message),"%s",msg_start);
        entry.message[strcspn(entry.message,"\n")]=0;
        check_alert(&entry);
        log_buffer_push(buf,entry);
    }
    fclose(f);
    return buf->count;
}
int parse_jornalctl_live(LogBuffer *buf,int max_lines){
    FILE *pipe=popen("journalctl -o short-iso -n 100 --no-pager","r");
    if (!pipe) return -1;
    char line[512];
    int read_count=0;
    while (fgets(line,sizeof(line),pipe) && read_count<max_lines){
        LogEntry entry;
        memset(&entry,0,sizeof(entry));
        char *space1=strchr(line,' ');
        if (!space1) continue;
        int ts_len=space1-line;
        if (ts_len>=(int)sizeof(entry.timestamp)) ts_len=sizeof(entry.timestamp)-1;
        memcpy(entry.timestamp,line,ts_len);
        entry.timestamp[ts_len]=0;
        char *p=space1+1;
        char *space2=strchr(p,' ');
        if (!space2) continue;
        int src_len=space2-p;
        if (src_len>=(int)sizeof(entry.source)) src_len=sizeof(entry.source)-1;
        memcpy(entry.source,p,src_len);
        entry.source[src_len]=0;
        snprintf(entry.message,sizeof(entry.message),"%s",space2+1);
        entry.message[strcspn(entry.message,"\n")]=0;
        check_alert(&entry);
        log_buffer_push(buf,entry);
        read_count++;
    }
    pclose(pipe);
    return read_count;
}