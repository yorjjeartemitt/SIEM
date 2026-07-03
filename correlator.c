#include <stdio.h>
static void syslog_checker(){
	char line[64];
	int i=0;
	FILE *f=fopen("/var/log/pacman.log","r");
	while (fgets(line,sizeof(line),f)!=NULL && i<10){
		printf(line);
		i++;
	}
	if (f) fclose(f);
}
int main(){
	syslog_checker();
	return 0;
}
