#include <stdio.h>
#include <string.h>
typedef struct {
	char timestamp[64];
	char hostname[128];
	char severity[16];
	char source[64];
	char message[1024];
	char raw[2048];
	int format_id;
} LogEntry;

int parse_log(const char *raw_line,LogEntry *entry){
	strncpy(entry->timestamp,"UNKNOWN",sizeof(entry->timestamp));
	entry->timestamp[sizeof(entry->timestamp)-1]='\0';
	strncpy(entry->hostname,"UNKNOWN",sizeof(entry->hostname));
	entry->hostname[sizeof(entry->hostname)-1]='\0';
	strncpy(entry->severity,"UNKNOWN",sizeof(entry->severity));
	entry->severity[sizeof(entry->severity)-1]='\0';
	strncpy(entry->source,"UNKNOWN",sizeof(entry->source));
	entry->source[sizeof(entry->source)-1]='\0';
	strncpy(entry->message,"UNKNOWN",sizeof(entry->message));
	entry->message[sizeof(entry->message)-1]='\0';	
	strncpy(entry->raw,"UNKNOWN",sizeof(entry->raw));
	entry->raw[sizeof(entry->raw)-1]='\0';

	entry->format_id=-1;
	return 1;

}
int main(){
	LogEntry entry;
	parse_log("test log line",&entry);
	printf("%s\n%s\n%s\n%s\n%s\n%s",entry.timestamp,entry.hostname,entry.severity,entry.source,entry.message,entry.raw);
	return 0;
}