#include <gtk/gtk.h>
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
static GtkWidget* make_menu_item(const char *label,GCallback callback,gpointer data){
	GtkWidget *item=gtk_menu_item_new_with_label(label);
	if (callback) g_signal_connect(item,"activate",callback,data);
	return item;
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
static void activate(GtkApplication *app, gpointer data){
	GtkWidget *window=gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window),"SIEM");
	gtk_window_set_default_size(GTK_WINDOW(window),600,700);

	GtkWidget *box=gtk_box_new(GTK_ORIENTATION_VERTICAL,5);
	gtk_container_add(GTK_CONTAINER(window),box);
	menu_bar(box,app);

	GtkWidget *scroll=gtk_scrolled_window_new(NULL,NULL);
	gtk_box_pack_start(GTK_BOX(box),scroll,TRUE,TRUE,0);

	GtkWidget *tree=gtk_tree_view_new();
	gtk_container_add(GTK_CONTAINER(scroll),tree);
	
	GtkListStore *store=gtk_list_store_new(5 ,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);
	for (int i=0; i<10;i++){
		GtkTreeIter iter;
		char pid_str[16];
		snprintf(pid_str,sizeof(pid_str),"%d",1529+i);
		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter, 0, pid_str, 1, "2026-01-23", 2, "PACMAN", 3, "test message",4,"726kb");
	}	
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),gtk_tree_view_column_new_with_attributes("PID",gtk_cell_renderer_text_new(),"text",0,NULL));
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),gtk_tree_view_column_new_with_attributes("Time",gtk_cell_renderer_text_new(),"text",1,NULL));
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),gtk_tree_view_column_new_with_attributes("Source",gtk_cell_renderer_text_new(),"text",2,NULL));
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),gtk_tree_view_column_new_with_attributes("Message",gtk_cell_renderer_text_new(),"text",3,NULL));
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree),gtk_tree_view_column_new_with_attributes("File Size",gtk_cell_renderer_text_new(),"text",4,NULL));

	gtk_tree_view_set_model(GTK_TREE_VIEW(tree),GTK_TREE_MODEL(store));
	g_object_unref(store);
	gtk_widget_show_all(window);

}

int main(int argc,char *argv[]){
	GtkApplication *app=gtk_application_new("org.siem.app",G_APPLICATION_DEFAULT_FLAGS);
	g_signal_connect(app,"activate",G_CALLBACK(activate),NULL);
	int status=g_application_run(G_APPLICATION(app),argc,argv);
	g_object_unref(app);
	return status;
}
