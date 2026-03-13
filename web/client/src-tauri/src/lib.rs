use std::sync::Mutex;
use std::thread;

use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::TrayIconEvent;
use tauri::{Manager, WindowEvent};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::ShellExt;

struct DaemonChild(Mutex<Option<CommandChild>>);

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn handle_deep_link_url(app: &tauri::AppHandle, url: &str) {
    let prefix = "burrow://invite/";
    if let Some(invite_data) = url.strip_prefix(prefix) {
        let invite_data = invite_data.trim_end_matches('/');
        if invite_data.is_empty() {
            return;
        }
        let payload = serde_json::json!({ "invite": invite_data });
        thread::spawn(move || {
            let client = reqwest::blocking::Client::new();
            let _ = client
                .post("http://127.0.0.1:9090/api/servers")
                .json(&payload)
                .send();
        });
        show_window(app);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            window.set_title("Burrow VPN").unwrap();

            let shell = app.shell();
            let sidecar = shell.sidecar("burrow-vpn").unwrap();
            let (mut _rx, child) = sidecar
                .args(["daemon"])
                .spawn()
                .expect("failed to start burrow daemon");

            app.manage(DaemonChild(Mutex::new(Some(child))));

            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    handle_deep_link_url(&handle, url.as_str());
                }
            });

            let show = MenuItemBuilder::with_id("show", "Show").build(app)?;
            let connect = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
            let disconnect = MenuItemBuilder::with_id("disconnect", "Disconnect").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

            let menu = MenuBuilder::new(app)
                .item(&show)
                .separator()
                .item(&connect)
                .item(&disconnect)
                .separator()
                .item(&quit)
                .build()?;

            let tray = app.tray_by_id("main").expect("no tray icon found");
            tray.set_menu(Some(menu))?;

            tray.on_menu_event(move |app, event| match event.id().as_ref() {
                "show" => {
                    show_window(app);
                }
                "connect" => {
                    thread::spawn(|| {
                        let client = reqwest::blocking::Client::new();
                        let _ = client
                            .post("http://127.0.0.1:9090/api/connect")
                            .json(&serde_json::json!({}))
                            .send();
                    });
                }
                "disconnect" => {
                    thread::spawn(|| {
                        let client = reqwest::blocking::Client::new();
                        let _ = client
                            .post("http://127.0.0.1:9090/api/disconnect")
                            .send();
                    });
                }
                "quit" => {
                    let state = app.state::<DaemonChild>();
                    if let Ok(mut guard) = state.0.lock() {
                        if let Some(child) = guard.take() {
                            let _ = child.kill();
                        }
                    }
                    app.exit(0);
                }
                _ => {}
            });

            tray.on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click { .. } = event {
                    show_window(tray.app_handle());
                }
            });

            let main_window = app.get_webview_window("main").unwrap();
            let main_window_clone = main_window.clone();
            main_window.on_window_event(move |event| {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = main_window_clone.hide();
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
