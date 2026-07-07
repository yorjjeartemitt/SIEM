#include <gtk/gtk.h>
#include "log.h"
typedef struct{
	GtkWidget *tree;
	GtkTreeStore *store;
	LogBuffer current_buf;
	int show_all;
} AppWidgets;
static void set_dark(GtkMenuItem *item,gpointer data){
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",TRUE,NULL);
}
static void set_white(GtkMenuItem *item,gpointer data){
	GtkSettings *settings=gtk_settings_get_default();
	g_object_set(settings,"gtk-application-prefer-dark-theme",FALSE,NULL);
}
static void quit(GtkMenuItem *item,gpointer data){
	g_application_quit(G_APPLICATION(data));
}
static void toggle_for_theme(GtkWindow *window,gpointer data){
	GtkSettings *settings=gtk_settings_get_default();
	gboolean is_dark;
	g_object_get(settings,"gtk-application-prefer-dark-theme",&is_dark,NULL);
	g_object_set(settings,"gtk-application-prefer-dark-theme",!is_dark,NULL);
}
static GtkWidget* make_menu_item(const char *label,GCallback callback,gpointer data){
	GtkWidget *item=gtk_menu_item_new_with_label(label);
	if (callback) g_signal_connect(item,"activate",callback,data);
	return item;
}
static void reload_tree_from_buffer(AppWidgets *aw,LogBuffer *buf){
	for (int i=0; i<buf->count;i++){
		if (!aw->show_all && !buf->data[i].is_alert) continue;
		char short_msg[64];
		snprintf(short_msg,sizeof(short_msg),"%.60s%s",buf->data[i].message,strlen(buf->data[i].message)>60?"...":"");
		GtkTreeIter parent_iter,child_iter;
		gtk_tree_store_append(aw->store,&parent_iter,NULL);
		const char *status=buf->data[i].is_alert ? "ALERT":"OK";
		gtk_tree_store_set(aw->store,&parent_iter,0,"",1,buf->data[i].timestamp,2,buf->data[i].source,3,short_msg,4,status,5,buf->data[i].reason,6,"",-1);
		gtk_tree_store_append(aw->store,&child_iter,&parent_iter);
		gtk_tree_store_set(aw->store,&child_iter,0,"",1,"",2,"",3,buf->data[i].message,4,"",5,"",6,"",-1);
	}
}
static void on_toggle_show_all(GtkToggleButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);

	aw->show_all=gtk_toggle_button_get_active(btn);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void on_source_pacman(GtkButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);
	log_buffer_free(&aw->current_buf);
	log_buffer_init(&aw->current_buf,1000);
	parse_pacman_log("/var/log/pacman.log",&aw->current_buf);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void on_source_auth(GtkButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);

	log_buffer_free(&aw->current_buf);
	log_buffer_init(&aw->current_buf,1000);
	parse_auth_log("/var/log/auth.log",&aw->current_buf);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void on_source_journal(GtkButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);
	log_buffer_free(&aw->current_buf);
	log_buffer_init(&aw->current_buf,1000);
	parse_jornalctl_live(&aw->current_buf,100);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void on_open_file(GtkMenuItem *item,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	GtkWidget *dialog=gtk_file_chooser_dialog_new("Open log file",NULL,GTK_FILE_CHOOSER_ACTION_OPEN,"_Cancel",GTK_RESPONSE_CANCEL,"_Open",GTK_RESPONSE_ACCEPT,NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog))==GTK_RESPONSE_ACCEPT){
		char *filename=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		gtk_tree_store_clear(aw->store);
		log_buffer_free(&aw->current_buf);
		log_buffer_init(&aw->current_buf,1000);
		parse_generic_log(filename,&aw->current_buf);
		reload_tree_from_buffer(aw,&aw->current_buf);
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
}
static void on_source_all(GtkButton *btn,gpointer data){
	AppWidgets *aw=(AppWidgets*)data;
	gtk_tree_store_clear(aw->store);
	log_buffer_free(&aw->current_buf);
	log_buffer_init(&aw->current_buf,1000);
	parse_pacman_log("/var/log/pacman.log",&aw->current_buf);
	parse_auth_log("/var/log/auth.log",&aw->current_buf);
	parse_jornalctl_live(&aw->current_buf,100);
	reload_tree_from_buffer(aw,&aw->current_buf);
}
static void start_capture(GtkToolButton *btn,gpointer data){
	g_print("Start capture (stub)\n"); 
}
static void stop_capture(GtkToolButton *btn,gpointer data){
	g_print("Stop capture (stub)\n");
}
static void clear_view(GtkToolButton *btn,gpointer data){
	g_print("Clear View (stub)\n");
}
static void menu_bar(GtkWidget *box,GtkApplication *app,AppWidgets *aw){
	GtkWidget *menubar=gtk_menu_bar_new();

	GtkWidget *file_menu=gtk_menu_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Open log file",G_CALLBACK(on_open_file),aw));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("New session",G_CALLBACK(NULL),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Export logs",G_CALLBACK(NULL),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),make_menu_item("Preferences",G_CALLBACK(NULL),NULL));
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
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Live log stream",G_CALLBACK(NULL),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Alerts",G_CALLBACK(NULL),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("Toggle sidebar",G_CALLBACK(NULL),NULL));
	gtk_menu_shell_append(GTK_MENU_SHELL(view_menu),make_menu_item("fullscreen",G_CALLBACK(NULL),NULL));


	GtkWidget *view_item=gtk_menu_item_new_with_label("View");
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(view_item),view_menu);
	gtk_menu_shell_append(GTK_MENU_SHELL(menubar),view_item);


	gtk_box_pack_start(GTK_BOX(box),menubar,FALSE,FALSE,0);
}
static GtkWidget* build_toolbar(void){
	GtkWidget *toolbar=gtk_toolbar_new();
	gtk_toolbar_set_style(GTK_TOOLBAR(toolbar),GTK_TOOLBAR_ICONS);
	gtk_toolbar_set_icon_size(GTK_TOOLBAR(toolbar),GTK_ICON_SIZE_SMALL_TOOLBAR);

	GtkToolItem *start_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(start_btn),"media-playback-start");
	g_signal_connect(start_btn,"clicked",G_CALLBACK(start_capture),NULL);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),start_btn,-1);

	GtkToolItem *stop_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(stop_btn),"media-playback-stop");
	g_signal_connect(stop_btn,"clicked",G_CALLBACK(stop_capture),NULL);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),stop_btn,-1);

	GtkToolItem *sep=gtk_separator_tool_item_new();
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),sep,-1);

	GtkToolItem *clear_btn=gtk_tool_button_new(NULL,NULL);
	gtk_tool_button_set_icon_name(GTK_TOOL_BUTTON(clear_btn),"edit-clear");
	g_signal_connect(clear_btn,"clicked",G_CALLBACK(clear_view),NULL);
	gtk_toolbar_insert(GTK_TOOLBAR(toolbar),clear_btn,-1);
	return toolbar;

}

static GtkWidget* left_panel_analyst(AppWidgets *aw){
	GtkWidget *panel=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_widget_set_size_request(panel,100,-1);
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

	GtkWidget *ml_up=gtk_check_button_new_with_label("Enable ML");
	gtk_box_pack_start(GTK_BOX(panel),ml_up,FALSE,FALSE,0);

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

	GtkTreeStore *store=gtk_tree_store_new(7,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree),GTK_TREE_MODEL(store));

	AppWidgets *aw=malloc(sizeof(AppWidgets));
	aw->tree=tree;
	aw->store=store;
	aw->show_all=0;
	log_buffer_init(&aw->current_buf,1000);
	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_container_add(GTK_CONTAINER(window),box);
	menu_bar(box,app,aw);
	
	GtkWidget *toolbar=build_toolbar();
	gtk_box_pack_start(GTK_BOX(box),toolbar,FALSE,FALSE,0);

	GtkWidget *left_panel=left_panel_analyst(aw);
	gtk_paned_pack1(GTK_PANED(paned),left_panel,FALSE,FALSE);
	gtk_paned_pack2(GTK_PANED(paned),scroll,TRUE,FALSE);
	gtk_box_pack_start(GTK_BOX(box),paned,TRUE,TRUE,0);

	GtkTreeViewColumn *col;
	col=gtk_tree_view_column_new_with_attributes("PID",gtk_cell_renderer_text_new(),"text",0,NULL);
	gtk_tree_view_column_set_sort_column_id(col,0);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);

	col=gtk_tree_view_column_new_with_attributes("Time",gtk_cell_renderer_text_new(),"text",1,NULL);
	gtk_tree_view_column_set_sort_column_id(col,1);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);

	col=gtk_tree_view_column_new_with_attributes("Source",gtk_cell_renderer_text_new(),"text",2,NULL);
	gtk_tree_view_column_set_sort_column_id(col,2);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);

	col=gtk_tree_view_column_new_with_attributes("Message",gtk_cell_renderer_text_new(),"text",3,NULL);
	gtk_tree_view_column_set_sort_column_id(col,3);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);
	
	col=gtk_tree_view_column_new_with_attributes("Status",gtk_cell_renderer_text_new(),"text",4,NULL);
	gtk_tree_view_column_set_sort_column_id(col,4);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);

	col=gtk_tree_view_column_new_with_attributes("Reason",gtk_cell_renderer_text_new(),"text",5,NULL);
	gtk_tree_view_column_set_sort_column_id(col,5);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),col);
	
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
