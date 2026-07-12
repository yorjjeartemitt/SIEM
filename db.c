#include "db.h"
#include <string.h>
#include <stdio.h>

int db_open(sqlite3 **db,const char *path){
	if (sqlite3_open(path,db)!=SQLITE_OK) return -1;
   const char *schema =
		"CREATE TABLE IF NOT EXISTS logs ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"timestamp TEXT,"
		"timestamp_sec TEXT,"
		"source TEXT,"
		"message TEXT,"
		"level TEXT,"
		"is_alert INTEGER,"
		"reason TEXT,"
		"severity TEXT,"
		"category TEXT,"
		"verdict TEXT DEFAULT '',"
		"UNIQUE(timestamp_sec, source, message)"
		");"
		"CREATE TABLE IF NOT EXISTS app_state ("
		"key TEXT PRIMARY KEY,"
		"value TEXT"
		");";
	char *error_msg=NULL;
	if (sqlite3_exec(*db,schema,NULL,NULL,&error_msg)!=SQLITE_OK){
		fprintf(stderr, "db schema error: %s\n",error_msg);
		sqlite3_free(error_msg);
		return -1;
	}
	return 0;
}
void db_close(sqlite3 *db){
	if (db) sqlite3_close(db);
}
void db_insert_log(sqlite3 *db,const LogEntry *entry){
	const char *sql="INSERT OR IGNORE INTO logs " "(timestamp,timestamp_sec,source,message,level,is_alert,reason,severity,category,verdict) " "VALUES (?,?,?,?,?,?,?,?,?,?);";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return;
	sqlite3_bind_text(stmt,1,entry->timestamp,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,entry->timestamp_sec,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,3,entry->source,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,4,entry->message,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,5,entry->level,-1,SQLITE_STATIC);
	sqlite3_bind_int(stmt,6,entry->is_alert);
	sqlite3_bind_text(stmt,7,entry->reason,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,8,entry->severity,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,9,entry->category,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,10,entry->verdict,-1,SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
void db_set_verdict(sqlite3 *db,const LogEntry *entry,const char *verdict){
	db_insert_log(db,entry);
	const char *sql="UPDATE logs SET verdict=? " "WHERE timestamp_sec=? AND source=? AND message=?;";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return;
	sqlite3_bind_text(stmt,1,verdict,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,entry->timestamp_sec,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,3,entry->source,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,4,entry->message,-1,SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int db_get_verdict(sqlite3 *db,const LogEntry *entry,char *out,size_t out_size){
	const char *sql="SELECT verdict FROM logs WHERE timestamp_sec=? AND source=? AND message=?;";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return 0;
	sqlite3_bind_text(stmt,1,entry->timestamp_sec,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,entry->source,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,3,entry->message,-1,SQLITE_STATIC);
	int found=0;
	if (sqlite3_step(stmt)==SQLITE_ROW){
		const char *v=(const char*)sqlite3_column_text(stmt,0);
		if (v && v[0]){
			snprintf(out,out_size,"%s",v);
			found=1;
		}
	}
	sqlite3_finalize(stmt);
	return found;
}
int db_load_all_logs(sqlite3 *db,LogBuffer *buf){
	const char *sql="SELECT timestamp,timestamp_sec,source,message,level,is_alert,reason,severity,category,verdict " "FROM logs ORDER BY id ASC";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return 0;
	int count=0;
	while (sqlite3_step(stmt)==SQLITE_ROW){
		LogEntry entry;
		memset(&entry,0,sizeof(entry));
		snprintf(entry.timestamp,sizeof(entry.timestamp),"%s",(const char *)sqlite3_column_text(stmt,0));
		snprintf(entry.timestamp_sec,sizeof(entry.timestamp_sec),"%s",(const char *)sqlite3_column_text(stmt,1));
		snprintf(entry.source,sizeof(entry.source),"%s",(const char *)sqlite3_column_text(stmt,2));
		snprintf(entry.message,sizeof(entry.message),"%s",(const char *)sqlite3_column_text(stmt,3));
		snprintf(entry.level,sizeof(entry.level),"%s",(const char *)sqlite3_column_text(stmt,4));
		entry.is_alert=sqlite3_column_int(stmt,5);
		snprintf(entry.reason,sizeof(entry.reason),"%s",(const char *)sqlite3_column_text(stmt,6));
		snprintf(entry.severity,sizeof(entry.severity),"%s",(const char *)sqlite3_column_text(stmt,7));
		snprintf(entry.category,sizeof(entry.category),"%s",(const char *)sqlite3_column_text(stmt,8));
		snprintf(entry.verdict,sizeof(entry.verdict),"%s",(const char *)sqlite3_column_text(stmt,9));
		log_buffer_push(buf,entry);
		count++;
	}
	sqlite3_finalize(stmt);
	return count;
}
void db_set_state(sqlite3 *db,const char *key,const char *value){
	const char *sql="INSERT INTO app_state (key,value) VALUES (?,?) " "ON CONFLICT(key) DO UPDATE SET value=excluded.value;";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return;
	sqlite3_bind_text(stmt,1,key,-1,SQLITE_STATIC);
	sqlite3_bind_text(stmt,2,value,-1,SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int db_get_state(sqlite3 *db,const char *key,char *out,size_t out_size){
	const char *sql="SELECT value FROM app_state WHERE key=?;";
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)!=SQLITE_OK) return 0;
	sqlite3_bind_text(stmt,1,key,-1,SQLITE_STATIC);
	int found=0;
	if (sqlite3_step(stmt)==SQLITE_ROW){
		snprintf(out,out_size,"%s",(const char *)sqlite3_column_text(stmt,0));
		found=1;
	}
	sqlite3_finalize(stmt);
	return found;
}