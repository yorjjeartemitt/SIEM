#ifndef DB_H
#define DB_H
#include <sqlite3.h>
#include "log.h"
int db_open(sqlite3 **db,const char *path);
void db_close(sqlite3 *db);

void db_insert_log(sqlite3 *db,const LogEntry *entry);
void db_set_verdict(sqlite3 *db,const LogEntry *entry,const char *verdict);
int db_get_verdict(sqlite3 *db,const LogEntry *entry,char *out,size_t out_size);
int db_load_all_logs(sqlite3 *db,LogBuffer *buf);

void db_set_state(sqlite3 *db,const char *key,const char *value);
int db_get_state(sqlite3 *db,const char *key,char *out,size_t out_size);
#endif