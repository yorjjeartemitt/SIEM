#include <gtk/gtk.h>
#include "log.h"
#include <string.h>
typedef enum{
	SRC_NONE,SRC_ALL,SRC_SYSTEM,SRC_AUTH,SRC_PACMAN
} SourceType;
typedef struct{
	GtkWidget *tree;
	GtkWidget *window;
	GtkTreeStore *store;
	GtkTreeViewColumn *cols[7];
	GtkWidget *stack;
	LogBuffer current_buf;
	guint capture_timer_id;
	gboolean is_capturing;
	int page_offset;
	int page_size;
	int show_all;
	int col_count;
	SourceType active_source;
	GtkWidget *status_label;
	long auth_log_offset;
	long pacman_log_offset;
	char last_jounal_ts[32];
	GtkWidget *left_panel;
	gboolean sidebar_visible;
} AppWidgets;
static void set_dark(GtkMenuItem *item,gpointer data){
	(void)item;(void)data;
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",TRUE,NULL);
}
static void set_white(GtkMenuItem *item,gpointer data){
	(void)item;(void)data;
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",FALSE,NULL);
}
static void quit(GtkMenuItem *item,gpointer data){
	g_application_quit(G_APPLICATION(data));
}
static void toggle_for_theme(GtkWindow *window,gpointer data){
	(void)window;(void)data;
	GtkSettings *settings=gtk_settings_get_default();
	gboolean is_dark;
	g_object_get(settings,"gtk-application-prefer-dark-theme",&is_dark,NULL);
	g_object_set(settings,"gtk-application-prefer-dark-theme",!is_dark,NULL);
}
static gboolean is_fullscreen=FALSE;
static void toggle_fullscreen(GtkMenuItem *item,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	if (is_fullscreen){
		gtk_window_unfullscreen(GTK_WINDOW(aw->window));
	} else{
		gtk_window_fullscreen(GTK_WINDOW(aw->window));
	}
	is_fullscreen=!is_fullscreen;
}
static GtkWidget* make_menu_item(const char *label,GCallback callback,gpointer data){
	GtkWidget *item=gtk_menu_item_new_with_label(label);
	if (callback) g_signal_connect(item,"activate",callback,data);
	return item;
}
static void append_page_to_tree(AppWidgets *aw,LogBuffer *buf){
	int shown=0;
	int skipped=0;
	int target_skip=aw->page_offset;
	for (int i=0; i<buf->count && shown<aw->page_size; i++){
		if (!aw->show_all && !buf->data[i].is_alert) continue;
		if (skipped<target_skip){ skipped++; continue; }
		char short_msg[64];
		snprintf(short_msg,sizeof(short_msg),"%.60s%s",buf->data[i].message,strlen(buf->data[i].message)>60?"...":"");
		char full_details[1024];
		snprintf(full_details,sizeof(full_details),"Time: %s\nSource: %s\nMessage: %s\nSeverity: %s\nReason: %s\nCategory: %s",buf->data[i].timestamp_sec,buf->data[i].source,buf->data[i].message,buf->data[i].severity,buf->data[i].reason,buf->data[i].category);
		GtkTreeIter parent_iter,child_iter;
		gtk_tree_store_append(aw->store,&parent_iter,NULL);
		gtk_tree_store_set(aw->store,&parent_iter,0,"",1,buf->data[i].timestamp,2,buf->data[i].source,3,short_msg,4,buf->data[i].severity,5,buf->data[i].reason,6,buf->data[i].category,7,buf->data[i].verdict,-1);
		gtk_tree_store_append(aw->store,&child_iter,&parent_iter);
		gtk_tree_store_set(aw->store,&child_iter,0,"",1,"",2,"",3,full_details,4,"",5,"",6,"",7,"",-1);
		shown++;
	}
}
static void reset_buffer(AppWidgets *aw){
	gtk_tree_store_clear(aw->store);
	log_buffer_free(&aw->current_buf);
	log_buffer_init(&aw->current_buf,1000);
	aw->page_offset=0;
}

static void reload_tree_from_buffer(AppWidgets *aw,LogBuffer *buf){
	GtkAdjustment *vadj=gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(gtk_widget_get_parent(aw->tree)));
	gdouble saved_pos=gtk_adjustment_get_value(vadj);

	GtkTreeModel *model=gtk_tree_view_get_model(GTK_TREE_VIEW(aw->tree));
	g_object_ref(model);
	append_page_to_tree(aw,buf);
	gtk_tree_view_set_model(GTK_TREE_VIEW(aw->tree),model);
	g_object_unref(model);

	gtk_adjustment_set_value(vadj,saved_pos);
}
static void on_toggle_show_all(GtkToggleButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);

	aw->show_all=gtk_toggle_button_get_active(btn);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void load_source(AppWidgets *aw, SourceType src){
	reset_buffer(aw);
	switch(src){
		case SRC_PACMAN:
			parse_pacman_log_incremental("/var/log/pacman.log",&aw->current_buf,&aw->pacman_log_offset);
			break;
		case SRC_AUTH:
			parse_auth_log_incremental("/var/log/auth.log",&aw->current_buf,&aw->auth_log_offset);
			break;
		case SRC_SYSTEM:
			parse_journalctl_incremental(&aw->current_buf,aw->last_jounal_ts,sizeof(aw->last_jounal_ts));
			break;
		case SRC_ALL:
			parse_pacman_log_incremental("/var/log/pacman.log",&aw->current_buf,&aw->pacman_log_offset);
			parse_auth_log_incremental("/var/log/auth.log",&aw->current_buf,&aw->auth_log_offset);
			parse_journalctl_incremental(&aw->current_buf,aw->last_jounal_ts,sizeof(aw->last_jounal_ts));
			break;
		default: break;
	}
	aw->active_source=src;
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void new_session(GtkMenuItem *item,gpointer data){ (void)item; reset_buffer((AppWidgets*)data); }

static void on_source_pacman(GtkButton *btn,gpointer data){ (void)btn; load_source((AppWidgets*)data,SRC_PACMAN); }
static void on_source_auth(GtkButton *btn,gpointer data){ (void)btn; load_source((AppWidgets*)data,SRC_AUTH); }
static void on_source_journal(GtkButton *btn,gpointer data){ (void)btn; load_source((AppWidgets*)data,SRC_SYSTEM); }
static void on_source_all(GtkButton *btn,gpointer data){ (void)btn; load_source((AppWidgets*)data,SRC_ALL); }

static void on_window_destroy(GtkWidget *widget,gpointer data){
	(void)widget;
	AppWidgets *aw=(AppWidgets*)data;
	if (aw->is_capturing) g_source_remove(aw->capture_timer_id);
	log_buffer_free(&aw->current_buf);
	free(aw);
}

static void on_open_file(GtkMenuItem *item,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	GtkWidget *dialog=gtk_file_chooser_dialog_new("Open log file",NULL,GTK_FILE_CHOOSER_ACTION_OPEN,"_Cancel",GTK_RESPONSE_CANCEL,"_Open",GTK_RESPONSE_ACCEPT,NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT){
		char *filename=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		if (filename) {
			reset_buffer(aw);
			parse_generic_log(filename,&aw->current_buf);
			reload_tree_from_buffer(aw,&aw->current_buf);
			g_free(filename);
		}
	}
	gtk_widget_destroy(dialog);
}
static void on_scroll_edge_reached(GtkScrolledWindow *sw,GtkPositionType pos,gpointer data){
	if (pos!=GTK_POS_BOTTOM) return;
	AppWidgets *aw=(AppWidgets*)data;
	aw->page_offset+=aw->page_size;
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static gboolean capture_tick(gpointer data){
    AppWidgets *aw=(AppWidgets*)data;
    if (aw->active_source==SRC_NONE) return G_SOURCE_CONTINUE;

    int before=aw->current_buf.count;

    switch(aw->active_source){
        case SRC_PACMAN:
            parse_pacman_log_incremental("/var/log/pacman.log",&aw->current_buf,&aw->pacman_log_offset);
            break;
        case SRC_AUTH:
            parse_auth_log_incremental("/var/log/auth.log",&aw->current_buf,&aw->auth_log_offset);
            break;
        case SRC_SYSTEM:
            parse_journalctl_incremental(&aw->current_buf,aw->last_jounal_ts,sizeof(aw->last_jounal_ts));
            break;
        case SRC_ALL:
            parse_pacman_log_incremental("/var/log/pacman.log",&aw->current_buf,&aw->pacman_log_offset);
            parse_auth_log_incremental("/var/log/auth.log",&aw->current_buf,&aw->auth_log_offset);
            parse_journalctl_incremental(&aw->current_buf,aw->last_jounal_ts,sizeof(aw->last_jounal_ts));
            break;
        default: break;
    }

    if (aw->current_buf.count>before){
        for (int i=before;i<aw->current_buf.count;i++){
            LogEntry *e=&aw->current_buf.data[i];
            if (!aw->show_all && !e->is_alert) continue;
            char short_msg[64];
            snprintf(short_msg,sizeof(short_msg),"%.60s%s",e->message,strlen(e->message)>60?"...":"");
            GtkTreeIter parent_iter,child_iter;
            gtk_tree_store_append(aw->store,&parent_iter,NULL);
            gtk_tree_store_set(aw->store,&parent_iter,0,"",1,e->timestamp,2,e->source,3,short_msg,4,e->severity,5,e->reason,6,e->category,7,e->verdict,-1);
            gtk_tree_store_append(aw->store,&child_iter,&parent_iter);
            gtk_tree_store_set(aw->store,&child_iter,0,"",1,"",2,"",3,e->message,4,"",5,"",6,"",7,"",-1);
        }
    }
    return G_SOURCE_CONTINUE;
}
static void mark_tp(GtkToolButton *btn,gpointer data){
	(void)btn;
	AppWidgets *aw=(AppWidgets*)data;
	GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(aw->tree));
	GtkTreeModel *model;
	GtkTreeIter iter;
	if (!gtk_tree_selection_get_selected(sel,&model,&iter)) return;
	GtkTreeIter parent;
	if (gtk_tree_model_iter_parent(model,&parent,&iter)) iter=parent;
	gtk_tree_store_set(aw->store,&iter,7,"TP",-1);
}
static void mark_fp(GtkToolButton *btn,gpointer data){
	(void)btn;
	AppWidgets *aw=(AppWidgets*)data;
	GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(aw->tree));
	GtkTreeModel *model;
	GtkTreeIter iter;
	if (!gtk_tree_selection_get_selected(sel,&model,&iter)) return;
	GtkTreeIter parent;
	if (gtk_tree_model_iter_parent(model,&parent,&iter)) iter=parent;
	gtk_tree_store_set(aw->store,&iter,7,"FP",-1);
}
static void start_capture(GtkToolButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	if (aw->is_capturing) return;
	aw->is_capturing=TRUE;
	aw->capture_timer_id=g_timeout_add(2000,capture_tick,aw);
	gtk_label_set_text(GTK_LABEL(aw->status_label)," ● REC ");
}
static void stop_capture(GtkToolButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	if (!aw->is_capturing) return;
	g_source_remove(aw->capture_timer_id);
	aw->is_capturing=FALSE;
	gtk_label_set_text(GTK_LABEL(aw->status_label)," ○ stopped ");
}
static void clear_view(GtkToolButton *btn,gpointer data){ (void)btn; reset_buffer((AppWidgets*)data); }
static void switch_to_network(GtkMenuItem *item,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_stack_set_visible_child_name(GTK_STACK(aw->stack),"network");
}
static void switch_to_syslog(GtkMenuItem *item,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_stack_set_visible_child_name(GTK_STACK(aw->stack),"syslog");
}
static void toggle_col(GtkCheckMenuItem *item,gpointer data){
	GtkTreeViewColumn *col=(GtkTreeViewColumn*)data;
	gtk_tree_view_column_set_visible(col,gtk_check_menu_item_get_active(item));
}
static gboolean on_header_click(GtkWidget *widget,GdkEventButton *event,gpointer data){
	if (event->button!=3) return FALSE;
	AppWidgets *aw=(AppWidgets*)data;
	GtkWidget *menu=gtk_menu_new();
	for (int i=0;i<aw->col_count;i++){
		GtkWidget *item=gtk_check_menu_item_new_with_label(gtk_tree_view_column_get_title(aw->cols[i]));
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item),gtk_tree_view_column_get_visible(aw->cols[i]));
		g_signal_connect(item,"toggled",G_CALLBACK(toggle_col),aw->cols[i]);
		gtk_menu_shell_append(GTK_MENU_SHELL(menu),item);
	}
	gtk_widget_show_all(menu);
	gtk_menu_popup_at_pointer(GTK_MENU(menu),NULL);
	return TRUE;
}
static void toggle_sidebar(GtkMenuItem *item,gpointer data){
	(void)item;
	AppWidgets *aw=(AppWidgets*)data;
	aw->sidebar_visible=!aw->sidebar_visible;
	gtk_widget_set_visible(aw->left_panel,aw->sidebar_visible);
}
static void export_logs(GtkMenuItem *item,gpointer data){
	(void)item;
	AppWidgets *aw=(AppWidgets*)data;
	GtkWidget *dialog=gtk_file_chooser_dialog_new("Export logs",GTK_WINDOW(aw->window),GTK_FILE_CHOOSER_ACTION_SAVE,"_Cancel",GTK_RESPONSE_CANCEL,"_Save",GTK_RESPONSE_ACCEPT,NULL);
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog),"export.csv");
	if (gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT){
		char *filename=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		FILE *f=fopen(filename,"w");
		if (f){
			fprintf(f,"timestamp,source,message,severity,reason,category,verdict\n");
			for (int i=0;i<aw->current_buf.count;i++){
				LogEntry *e=&aw->current_buf.data[i];
				fprintf(f,"\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",e->timestamp,e->source,e->message,e->severity,e->reason,e->category,e->verdict);
			}
			fclose(f);
		}
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
}
static void menu_bar(GtkWidget *box,GtkApplication *app,AppWidgets *aw){
	GtkWidget *menubar=gtk_menu_bar_new();

	GtkWidget *file_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Open log file",G_CALLBACK(on_open_file),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("New session",G_CALLBACK(new_session),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Export logs",G_CALLBACK(export_logs),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Quit",G_CALLBACK(quit),app));
	
	GtkWidget *file_item=gtk_menu_item_new_with_label("File");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item),file_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),file_item);

	GtkWidget *theme_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(theme_menu),make_menu_item("Dark",G_CALLBACK(set_dark),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(theme_menu),make_menu_item("White",G_CALLBACK(set_white),NULL));

	GtkWidget *theme_item=gtk_menu_item_new_with_label("Theme");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(theme_item),theme_menu);

	GtkWidget *view_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),theme_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Live log stream",G_CALLBACK(start_capture),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Stop log stream",G_CALLBACK(stop_capture),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Toggle sidebar",G_CALLBACK(toggle_sidebar),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("fullscreen",G_CALLBACK(toggle_fullscreen),aw));

	GtkWidget *view_item=gtk_menu_item_new_with_label("View");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(view_item),view_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),view_item);

	GtkWidget *tools_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("Network view",G_CALLBACK(switch_to_network),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(tools_menu),make_menu_item("Syslog view",G_CALLBACK(switch_to_syslog),aw));

	GtkWidget *tools_item=gtk_menu_item_new_with_label("Tools");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(tools_item),tools_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),tools_item);

	gtk_box_pack_start(GTK_BOX(box),menubar,FALSE,FALSE,0);
}
static GtkWidget* build_toolbar(AppWidgets *aw){
	GtkWidget *toolbar=gtk_toolbar_new();
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar),GTK_TOOLBAR_ICONS);
	gtk_toolbar_set_icon_size(GTK_TOOLBAR(toolbar),GTK_ICON_SIZE_SMALL_TOOLBAR);

	GtkToolItem *start_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(start_btn),"media-playback-start");
	g_signal_connect(start_btn,"clicked",G_CALLBACK(start_capture),aw);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),start_btn,-1);

	GtkToolItem *stop_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(stop_btn),"media-playback-stop");
	g_signal_connect(stop_btn,"clicked",G_CALLBACK(stop_capture),aw);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),stop_btn,-1);

	GtkToolItem *sep=gtk_separator_tool_item_new();
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),sep,-1);

	GtkToolItem *clear_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(clear_btn),"edit-clear");
	g_signal_connect(clear_btn,"clicked",G_CALLBACK(clear_view),aw);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),clear_btn,-1);
	
	GtkToolItem *sep2=gtk_separator_tool_item_new();
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),sep2,-1);
	
	GtkToolItem *tp_btn=gtk_tool_button_new(NULL,"TP");
	g_signal_connect(tp_btn,"clicked",G_CALLBACK(mark_tp),aw);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),tp_btn,-1);

	GtkToolItem *fp_btn=gtk_tool_button_new(NULL,"FP");
	g_signal_connect(fp_btn,"clicked",G_CALLBACK(mark_fp),aw);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),fp_btn,-1);

	GtkToolItem *status_item=gtk_tool_item_new();
	aw->status_label=gtk_label_new(" ○ stopped ");
	gtk_container_add(GTK_CONTAINER(status_item),aw->status_label);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),status_item,-1);
	return toolbar;

}

static GtkWidget* left_panel_analyst(AppWidgets *aw){
	GtkWidget *panel=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_widget_set_size_request(panel,160,-1);
	GtkWidget *source_label=gtk_label_new("Source");
	gtk_box_pack_start(GTK_BOX(panel),source_label,FALSE,FALSE,0);

	GtkWidget *btn_all=gtk_button_new_with_label("All Sources");
	g_signal_connect(btn_all,"clicked",G_CALLBACK(on_source_all),aw);
	gtk_box_pack_start(GTK_BOX(panel),btn_all,FALSE,FALSE,0);

	GtkWidget *btn_system=gtk_button_new_with_label("System");
	gtk_widget_set_tooltip_text(btn_system,"journalctl");
	g_signal_connect(btn_system,"clicked",G_CALLBACK(on_source_journal),aw);
	gtk_box_pack_start(GTK_BOX(panel),btn_system,FALSE,FALSE,0);

	GtkWidget *btn_auth=gtk_button_new_with_label("Auth");
	gtk_widget_set_tooltip_text(btn_auth,"auth.log");
	g_signal_connect(btn_auth,"clicked",G_CALLBACK(on_source_auth),aw);
	gtk_box_pack_start(GTK_BOX(panel),btn_auth,FALSE,FALSE,0);

	GtkWidget *btn_pacman=gtk_button_new_with_label("Pacman");
	gtk_widget_set_tooltip_text(btn_pacman,"pacman.log");
	g_signal_connect(btn_pacman,"clicked",G_CALLBACK(on_source_pacman),aw);
	gtk_box_pack_start(GTK_BOX(panel),btn_pacman,FALSE,FALSE,0);

	gtk_box_pack_start(GTK_BOX(panel),gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),FALSE,FALSE,5);
	GtkWidget *scanner_label=gtk_label_new("Scanner");
	gtk_box_pack_start(GTK_BOX(panel),scanner_label,FALSE,FALSE,0);

	GtkWidget *scan_btn=gtk_button_new_with_label("Scan Network");
	gtk_box_pack_start(GTK_BOX(panel),scan_btn,FALSE,FALSE,0);

	GtkWidget *scan_progress=gtk_progress_bar_new();
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(scan_progress),0.73);
	gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(scan_progress),TRUE);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(scan_progress),"930 / 1240 completed");
	gtk_box_pack_start(GTK_BOX(panel),scan_progress,FALSE,FALSE,0);

	gtk_box_pack_start(GTK_BOX(panel),gtk_separator_new(GTK_ORIENTATION_HORIZONTAL),FALSE,FALSE,5);

	GtkWidget *show_all_cb=gtk_check_button_new_with_label("Show All Logs");
	g_signal_connect(show_all_cb,"toggled",G_CALLBACK(on_toggle_show_all),aw);
	gtk_box_pack_start(GTK_BOX(panel),show_all_cb,FALSE,FALSE,0);
	return panel;
}
static void activate(GtkApplication *app, gpointer data){
	GtkCssProvider *provider=gtk_css_provider_new();
	gtk_css_provider_load_from_data(provider,"menubar{padding:0px;min-height:0px;}" "menubar menuitem{padding:2px 6px}",-1,NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),GTK_STYLE_PROVIDER(provider),GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	GtkWidget *window=gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window),"SIEM");
	gtk_window_set_default_size(GTK_WINDOW(window),1100,750);
	
	GtkAccelGroup *accel_group=gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(window),accel_group);

	GClosure *closure=g_cclosure_new(G_CALLBACK(toggle_for_theme),NULL,NULL);
	gtk_accel_group_connect(accel_group,GDK_KEY_w,GDK_CONTROL_MASK,GTK_ACCEL_VISIBLE,closure);

	GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);
	GtkWidget *paned=gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);

	GtkWidget *tree=gtk_tree_view_new();
	gtk_container_add(GTK_CONTAINER(scroll),tree);

	GtkWidget *stack=gtk_stack_new();
	GtkWidget *network_placeholder=gtk_label_new("TODO: network capture");
	gtk_stack_add_named(GTK_STACK(stack),scroll,"syslog");
	gtk_stack_add_named(GTK_STACK(stack),network_placeholder,"network");

	GtkTreeStore *store=gtk_tree_store_new(8,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree),GTK_TREE_MODEL(store));
	AppWidgets *aw=malloc(sizeof(AppWidgets));
	aw->tree=tree;
	aw->store=store;
	aw->show_all=0;
	aw->page_offset=0;
	aw->page_size=350;
	aw->stack=stack;
	aw->col_count=7;
	aw->window=window;
	aw->is_capturing=FALSE;
	aw->capture_timer_id=0;
	aw->active_source=SRC_NONE;
	aw->status_label=0;
	aw->auth_log_offset=0;
	aw->pacman_log_offset=0;
	aw->last_jounal_ts[0]=0;
	g_signal_connect(window,"destroy",G_CALLBACK(on_window_destroy),aw);
	g_signal_connect(tree,"button-press-event",G_CALLBACK(on_header_click),aw);
	g_signal_connect(scroll,"edge-reached",G_CALLBACK(on_scroll_edge_reached),aw);

	log_buffer_init(&aw->current_buf,1000);
	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_container_add(GTK_CONTAINER(window),box);
	menu_bar(box,app,aw);
	
	GtkWidget *toolbar=build_toolbar(aw);
	gtk_box_pack_start(GTK_BOX(box),toolbar,FALSE,FALSE,0);

	GtkWidget *left_panel=left_panel_analyst(aw);
	aw->left_panel=left_panel;
	aw->sidebar_visible=TRUE;
	gtk_paned_pack1(GTK_PANED(paned),left_panel,FALSE,FALSE);
	gtk_paned_pack2(GTK_PANED(paned),stack,TRUE,FALSE);
	gtk_box_pack_start(GTK_BOX(box),paned,TRUE,TRUE,0);

	aw->cols[0]=gtk_tree_view_column_new_with_attributes("Time",gtk_cell_renderer_text_new(),"text",1,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[0],0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[0]);
	gtk_tree_view_column_set_resizable(aw->cols[0],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[0],30);

	aw->cols[1]=gtk_tree_view_column_new_with_attributes("Source",gtk_cell_renderer_text_new(),"text",2,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[1],1);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[1]);
	gtk_tree_view_column_set_resizable(aw->cols[1],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[1],30);

	aw->cols[2]=gtk_tree_view_column_new_with_attributes("Message",gtk_cell_renderer_text_new(),"text",3,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[2],2);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[2]);
	gtk_tree_view_column_set_resizable(aw->cols[2],TRUE);
	gtk_tree_view_column_set_expand(aw->cols[2],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[2],80);

	aw->cols[3]=gtk_tree_view_column_new_with_attributes("Severity",gtk_cell_renderer_text_new(),"text",4,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[3],3);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[3]);
	gtk_tree_view_column_set_resizable(aw->cols[3],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[3],30);
	
	aw->cols[4]=gtk_tree_view_column_new_with_attributes("Reason",gtk_cell_renderer_text_new(),"text",5,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[4],4);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[4]);
	gtk_tree_view_column_set_resizable(aw->cols[4],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[4],30);
	
	aw->cols[5]=gtk_tree_view_column_new_with_attributes("Category",gtk_cell_renderer_text_new(),"text",6,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[5],5);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[5]);
	gtk_tree_view_column_set_resizable(aw->cols[5],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[5],30);
	
	aw->cols[6]=gtk_tree_view_column_new_with_attributes("Verdict",gtk_cell_renderer_text_new(),"text",7,NULL);
	gtk_tree_view_column_set_sort_column_id(aw->cols[6],6);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),aw->cols[6]);
	gtk_tree_view_column_set_resizable(aw->cols[6],TRUE);
	gtk_tree_view_column_set_min_width(aw->cols[6],20);
	
	g_object_unref(store);
	gtk_widget_show_all(window);
	gtk_paned_set_position(GTK_PANED(paned),200);
}

int main(int argc,char *argv[]){
	GtkApplication *app=gtk_application_new("org.siem.app",G_APPLICATION_DEFAULT_FLAGS);
	g_signal_connect(app,"activate",G_CALLBACK(activate),NULL);
	int status=g_application_run(G_APPLICATION(app),argc,argv);
	g_object_unref(app);
	return status;
}
