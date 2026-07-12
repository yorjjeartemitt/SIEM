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

typedef struct {
    const char *pattern;
    const char *severity;
    const char *category;
} AlertRule;
static void format_timestamp(char *out,size_t out_size,const char *raw){
    int year,mon,day,hours,min,sec;
    if (sscanf(raw,"%d-%d-%dT%d:%d:%d",&year,&mon,&day,&hours,&min,&sec)==6){
        snprintf(out,out_size,"%02d.%02d %02d:%02d",day,mon,hours,min);
        return;
    }
    char mon_str[4];
    if (sscanf(raw,"%3s %d %d:%d:%d",mon_str,&day,&hours,&min,&sec)==5){
        static const char *months[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
        int m=0;
        for (int i=0;i<12;i++) if (!strcmp(mon_str,months[i])){m=i+1;break;}
        snprintf(out,out_size,"%02d.%02d %02d:%02d",day,m,hours,min);
        return;
    }
    snprintf(out,out_size,"%s",raw);
}
static void format_timestamp_sec(char *out,size_t out_size,const char *raw){
    int year,mon,day,hours,min,sec;
    if (sscanf(raw,"%d-%d-%dT%d:%d:%d",&year,&mon,&day,&hours,&min,&sec)==6){
        snprintf(out,out_size,"%02d.%02d %02d:%02d:%02d",day,mon,hours,min,sec);
        return;
    }
    char mon_str[4];
    if (sscanf(raw,"%3s %d %d:%d:%d",mon_str,&day,&hours,&min,&sec)==5){
        static const char *months[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
        int m=0;
        for (int i=0;i<12;i++) if (!strcmp(mon_str,months[i])){m=i+1;break;}
        snprintf(out,out_size,"%02d.%02d %02d:%02d:%02d",day,m,hours,min,sec);
        return;
    }
    snprintf(out,out_size,"%s",raw);
}
static const AlertRule rules[]={
    // CRITICAL
    {"segfault","CRITICAL","system"},
    {"kernel panic","CRITICAL","system"},
    {"out of memory","CRITICAL","system"},
    {"buffer overflow","CRITICAL","malware"},
    {"root access","CRITICAL","auth"},
    {"privilege escalation","CRITICAL","auth"},

    // HIGH - auth / security
    {"authentication failure","HIGH","auth"},
    {"failed password","HIGH","auth"},
    {"invalid user","HIGH","auth"},
    {"unauthorized","HIGH","auth"},
    {"permission denied","HIGH","auth"},
    {"access denied","HIGH","auth"},
    {"denied","HIGH","auth"},
    {"refused","HIGH","network"},
    {"connection reset","HIGH","network"},
    {"port scan","HIGH","recon"},
    {"brute force","HIGH","auth"},
    {"sql injection","HIGH","malware"},
    {"malware","HIGH","malware"},
    {"exploit","HIGH","malware"},
    {"backdoor","HIGH","malware"},
    {"checksum mismatch","HIGH","integrity"},
    {"signature invalid","HIGH","integrity"},
    {"file modified","HIGH","integrity"},

    // MEDIUM - generic errors
    {"error","MEDIUM","system"},
    {"failed","MEDIUM","system"},
    {"failure","MEDIUM","system"},
    {"timeout","MEDIUM","network"},
    {"disconnected","MEDIUM","network"},
    {"unreachable","MEDIUM","network"},
    {"exception","MEDIUM","system"},
    {"crash","MEDIUM","system"},
    {"corrupt","MEDIUM","integrity"},
    {"suspicious","MEDIUM","recon"},

    // LOW - worth noting
    {"warning","LOW","system"},
    {"retry","LOW","network"},
    {"deprecated","LOW","system"},
    {"slow response","LOW","network"},
    {"high latency","LOW","network"},

    {NULL,NULL,NULL}
};

static int severity_rank(const char *sev){
    if (!strcmp(sev,"CRITICAL")) return 4;
    if (!strcmp(sev,"HIGH")) return 3;
    if (!strcmp(sev,"MEDIUM")) return 2;
    if (!strcmp(sev,"LOW")) return 1;
    return 0;
}
static int contains_word(const char *haystack,const char *pattern){
    size_t plen=strlen(pattern);
    const char *p=haystack;
    while ((p=strstr(p,pattern))!=NULL){
        int ok_before=(p==haystack) || !isalnum((unsigned char)*(p-1));
        int ok_after=!isalnum((unsigned char)*(p+plen));
        if (ok_before && ok_after) return 1;
        p+=plen;
    }
    return 0;
}
void check_alert(LogEntry *entry){
    const char *best_severity="NONE";
    const char *best_category="none";
    const char *best_pattern=NULL;
    int best_rank=0;

    if (!strcmp(entry->level,"CRITICAL")){ best_severity="CRITICAL"; best_category="system"; best_pattern="level: CRITICAL"; best_rank=4; }
    else if (!strcmp(entry->level,"ERROR")){ best_severity="HIGH"; best_category="system"; best_pattern="level: ERROR"; best_rank=3; }
    else if (!strcmp(entry->level,"WARNING") || !strcmp(entry->level,"WARN")){ best_severity="MEDIUM"; best_category="system"; best_pattern="level: WARNING"; best_rank=2; }
    char lower_msg[256];
    int i;
    for (i=0;entry->message[i] && i<255;i++){
        lower_msg[i]=tolower((unsigned char)entry->message[i]);
    }
    lower_msg[i]=0;
    if ((strstr(entry->source,"ALPM") || strstr(entry->source,"PACMAN") || strstr(entry->source,"ALPM-SCRIPTLET")) && (strstr(lower_msg,"removed") || strstr(lower_msg,"installed") || strstr(lower_msg,"upgraded"))){
        entry->is_alert=0;
        snprintf(entry->severity,sizeof(entry->severity),"NONE");
        snprintf(entry->category,sizeof(entry->category),"none");
        entry->reason[0]=0;
        return;
    }
    if (strstr(entry->source,"ALPM-SCRIPTLET") && strncmp(entry->message,"==> ",4)==0){
        memmove(entry->message,entry->message+4,strlen(entry->message)-4+1);
    }
    for (int r=0; rules[r].pattern; r++){
        if (contains_word(lower_msg,rules[r].pattern)){
            int rank=severity_rank(rules[r].severity);
            if (rank>best_rank){
                best_rank=rank;
                best_severity=rules[r].severity;
                best_category=rules[r].category;
                best_pattern=rules[r].pattern;
            }
        }
    }

    if (best_rank>0){
        entry->is_alert=1;
        snprintf(entry->severity,sizeof(entry->severity),"%s",best_severity);
        snprintf(entry->category,sizeof(entry->category),"%s",best_category);
        snprintf(entry->reason,sizeof(entry->reason),"%s",best_pattern);
    }else{
        entry->is_alert=0;
        snprintf(entry->severity,sizeof(entry->severity),"NONE");
        snprintf(entry->category,sizeof(entry->category),"none");
        entry->reason[0]=0;
    }
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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);

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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
        check_alert(&entry);
        log_buffer_push(buf,entry);
        read_count++;
    }
    pclose(pipe);
    return read_count;
}
int parse_journalctl_incremental(LogBuffer *buf, char *last_timestamp, size_t ts_size,char *last_line,size_t line_size){
    char cmd[256];
    if (last_timestamp[0]){
        snprintf(cmd,sizeof(cmd),"journalctl -o short-iso --no-pager --since=\"%s\"",last_timestamp);
    } else {
        snprintf(cmd,sizeof(cmd),"journalctl -o short-iso -n 50 --no-pager");
    }
    FILE *pipe=popen(cmd,"r");
    if (!pipe) return -1;
    char line[512];
    int read_count=0;
    char newest_ts[32]={0};
    int skipping=(last_line[0]!=0);
    while (fgets(line,sizeof(line),pipe)){
        if (skipping){
            if (strcmp(line,last_line)==0){
                skipping=0;
            }
            continue;
        }
        LogEntry entry;
        memset(&entry,0,sizeof(entry));
        char *space1=strchr(line,' ');
        if (!space1) continue;
        int ts_len=space1-line;
        if (ts_len>=(int)sizeof(entry.timestamp)) ts_len=sizeof(entry.timestamp)-1;
        memcpy(entry.timestamp,line,ts_len);
        entry.timestamp[ts_len]=0;
        strncpy(newest_ts,entry.timestamp,sizeof(newest_ts)-1);

        char *p=space1+1;
        char *space2=strchr(p,' ');
        if (!space2) continue;
        int src_len=space2-p;
        if (src_len>=(int)sizeof(entry.source)) src_len=sizeof(entry.source)-1;
        memcpy(entry.source,p,src_len);
        entry.source[src_len]=0;
        snprintf(entry.message,sizeof(entry.message),"%s",space2+1);
        entry.message[strcspn(entry.message,"\n")]=0;
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
        check_alert(&entry);
        log_buffer_push(buf,entry);
        read_count++;
        strncpy(last_line,line,line_size-1);
        last_line[line_size-1]=0;
    }
    if (newest_ts[0]) snprintf(last_timestamp,ts_size,"%s",newest_ts);
    pclose(pipe);
    return read_count;
}
int parse_auth_log_incremental(const char *filepath,LogBuffer *buf,long *offset){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    fseek(f,*offset,SEEK_SET);
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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);
        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
        check_alert(&entry);
        log_buffer_push(buf,entry);
    }
    *offset=ftell(f);
    fclose(f);
    return buf->count;
}

int parse_pacman_log_incremental(const char *filepath,LogBuffer *buf,long *offset){
    FILE *f=fopen(filepath,"r");
    if (!f) return -1;
    fseek(f,0,SEEK_END);
    long file_size=ftell(f);
    if (*offset==0 && file_size>65536){
        long start=file_size-65536;
        fseek(f,start,SEEK_SET);
        char discard[512];
        fgets(discard,sizeof(discard),f);
    }else{
        fseek(f,*offset,SEEK_SET);
    }

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
        format_timestamp_sec(entry.timestamp_sec,sizeof(entry.timestamp_sec),entry.timestamp);

        char formatted[32];
        format_timestamp(formatted,sizeof(formatted),entry.timestamp);
        snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",formatted);
        check_alert(&entry);
        log_buffer_push(buf,entry);
    }
    *offset=ftell(f);
    fclose(f);
    return buf->count;
}