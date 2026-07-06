#include <gtk/gtk.h>
#include "log.h"
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
static void start_capture(GtkToolButton *btn,gpointer data){
	g_print("Start capture (stub)\n");
}
static void stop_capture(GtkToolButton *btn,gpointer data){
	g_print("Stop capture (stub)\n");
}
static void clear_view(GtkToolButton *btn,gpointer data){
	g_print("Clear View (stub)\n");
}
static void on_row_selected(GtkTreeSelection *selection,gpointer data){
	GtkWidget *full_msg_label=GTK_WIDGET(data);
	GtkTreeModel *model;
	GtkTreeIter iter;
	if (gtk_tree_selection_get_selected(selection,&model,&iter)){
		gchar *full_message;
		gtk_tree_model_get(model,&iter,6,&full_message,-1);
		gtk_label_set_text(GTK_LABEL(full_msg_label),full_message);
		g_free(full_message);
	}
}
static void menu_bar(GtkWidget *box,GtkApplication *app){
	GtkWidget *menubar=gtk_menu_bar_new();

	GtkWidget *file_menu=gtk_menu_new();
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

static GtkWidget* left_panel_analyst(void){
	GtkWidget *panel=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_widget_set_size_request(panel,100,-1);
	GtkWidget *source_label=gtk_label_new("Source");
	gtk_box_pack_start(GTK_BOX(panel),source_label,FALSE,FALSE,0);
	const char *sources[]={"System","Auth","Pacman"};
	const char *full_names[]={"journalctl","auth.log","pacman.log"};
	for (int i=0; i<3;i++){
		GtkWidget *btn=gtk_button_new_with_label(sources[i]);
		gtk_widget_set_tooltip_text(btn,full_names[i]);
		gtk_box_pack_start(GTK_BOX(panel),btn,FALSE,FALSE,0);
	}
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
	return panel;
}
static void activate(GtkApplication *app, gpointer data){
	GtkCssProvider *provider=gtk_css_provider_new();
	gtk_css_provider_load_from_data(provider,"menubar{padding:0px;min-height:0px;}" "menubar menuitem{padding:2px 6px}",-1,NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),GTK_STYLE_PROVIDER(provider),GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	GtkWidget *window=gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window),"SIEM");
	gtk_window_set_default_size(GTK_WINDOW(window),600,700);
	
	GtkAccelGroup *accel_group=gtk_accel_group_new();
	gtk_window_add_accel_group(GTK_WINDOW(window),accel_group);

	GClosure *closure=g_cclosure_new(G_CALLBACK(toggle_for_theme),NULL,NULL);
	gtk_accel_group_connect(accel_group,GDK_KEY_w,GDK_CONTROL_MASK,GTK_ACCEL_VISIBLE,closure);
	
	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_container_add(GTK_CONTAINER(window),box);
	menu_bar(box,app);
	
	GtkWidget *toolbar=build_toolbar();
	gtk_box_pack_start(GTK_BOX(box),toolbar,FALSE,FALSE,0);
	GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);
	GtkWidget *paned=gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
	GtkWidget *left_panel=left_panel_analyst();
	gtk_paned_pack1(GTK_PANED(paned),left_panel,FALSE,FALSE);
	gtk_paned_pack2(GTK_PANED(paned),scroll,TRUE,FALSE);
	gtk_box_pack_start(GTK_BOX(box),paned,TRUE,TRUE,0);

	GtkWidget *detail_label=gtk_label_new("Select a log entry to see full message");
	gtk_label_set_line_wrap(GTK_LABEL(detail_label),TRUE);
	gtk_label_set_selectable(GTK_LABEL(detail_label),TRUE);
	gtk_widget_set_halign(detail_label,GTK_ALIGN_START);
	gtk_box_pack_start(GTK_BOX(box),detail_label,FALSE,FALSE,5);
	GtkWidget *tree=gtk_tree_view_new();
	gtk_container_add(GTK_CONTAINER(scroll),tree);
	LogBuffer buf;
	log_buffer_init(&buf,1000);
	parse_pacman_log("/var/log/pacman.log",&buf);
	GtkTreeStore *store=gtk_tree_store_new(7,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);
	GtkTreeSelection *selection=gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
	g_signal_connect(selection,"changed",G_CALLBACK(on_row_selected),detail_label);
	for (int i=0; i<buf.count;i++){
		if (!buf.data[i].is_alert) continue;
		char short_msg[64];
		snprintf(short_msg,sizeof(short_msg),"%.60s%s",buf.data[i].message,strlen(buf.data[i].message)>60?"...":"");
		GtkTreeIter parent_iter,child_iter;

		gtk_tree_store_append(store,&parent_iter,NULL);
		gtk_tree_store_set(store,&parent_iter,0,"",1,buf.data[i].timestamp,2,buf.data[i].source,3,short_msg,4,"ALERT",5,buf.data[i].reason,6,"",-1);
		gtk_tree_store_append(store,&child_iter,&parent_iter);
		gtk_tree_store_set(store,&child_iter,0,"",1,"",2,"",3,buf.data[i].message,4,"",5,"",6,"",-1);
	}
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree),GTK_TREE_MODEL(store));
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
	log_buffer_free(&buf);
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
