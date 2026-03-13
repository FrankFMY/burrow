use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[cfg(desktop)]
use std::sync::Mutex;

#[cfg(desktop)]
use tauri::menu::{MenuBuilder, MenuItemBuilder};
#[cfg(desktop)]
use tauri::tray::TrayIconEvent;
#[cfg(desktop)]
use tauri::WindowEvent;

use tauri::{Manager, RunEvent};
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_notification::NotificationExt;

#[cfg(desktop)]
use tauri_plugin_shell::process::CommandChild;
#[cfg(desktop)]
use tauri_plugin_shell::ShellExt;
#[cfg(desktop)]
use tauri_plugin_updater::UpdaterExt;

const MAX_INVITE_LEN: usize = 4096;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(desktop)]
struct DaemonChild(Mutex<Option<CommandChild>>);

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(desktop)]
fn kill_daemon(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<DaemonChild>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(child) = guard.take() {
                let _ = child.kill();
            }
        }
    }
}

fn handle_deep_link_url(app: &tauri::AppHandle, url: &str) {
    let prefix = "burrow://connect/";
    if url.starts_with(prefix) {
        let invite_data = url.trim_end_matches('/');
        if invite_data.len() <= prefix.len() || invite_data.len() > MAX_INVITE_LEN {
            return;
        }
        let payload = serde_json::json!({ "invite": invite_data });
        thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("HTTP client init failed");
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
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_notification::init());

    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_window_state::Builder::new().build())
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                show_window(app);
            }));
    }

    let app = builder
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            window.set_title("Burrow VPN").unwrap();

            // Sidecar daemon management (desktop only)
            #[cfg(desktop)]
            {
                let shell = app.shell();
                let sidecar = shell.sidecar("burrow-vpn").unwrap();
                let (mut _rx, child) = sidecar
                    .args(["daemon"])
                    .spawn()
                    .expect("failed to start burrow daemon");

                app.manage(DaemonChild(Mutex::new(Some(child))));
            }

            // Deep link handler (universal)
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    handle_deep_link_url(&handle, url.as_str());
                }
            });

            // Auto-update check (desktop only)
            #[cfg(desktop)]
            {
                let update_handle = app.handle().clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(5));
                    tauri::async_runtime::block_on(async {
                        let updater = match update_handle.updater() {
                            Ok(u) => u,
                            Err(_) => return,
                        };
                        if let Ok(Some(update)) = updater.check().await {
                            let _ = update
                                .download_and_install(
                                    |_chunk: usize, _total: Option<u64>| {},
                                    || {},
                                )
                                .await;
                        }
                    });
                });
            }

            // System tray setup (desktop only)
            #[cfg(desktop)]
            {
                let show = MenuItemBuilder::with_id("show", "Show").build(app)?;
                let connect = MenuItemBuilder::with_id("connect", "Connect").build(app)?;
                let disconnect = MenuItemBuilder::with_id("disconnect", "Disconnect")
                    .enabled(false)
                    .build(app)?;
                let quit = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

                let connect_item = connect.clone();
                let disconnect_item = disconnect.clone();

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
                        let notify = app.clone();
                        thread::spawn(move || {
                            let client = reqwest::blocking::Client::builder()
                                .timeout(std::time::Duration::from_secs(10))
                                .build()
                                .expect("HTTP client init failed");
                            let prefs: serde_json::Value = client
                                .get("http://127.0.0.1:9090/api/preferences")
                                .send()
                                .and_then(|r| r.json())
                                .unwrap_or(serde_json::json!({}));
                            let result = client
                                .post("http://127.0.0.1:9090/api/connect")
                                .json(&serde_json::json!({
                                    "tun_mode": prefs.get("tun_mode").and_then(|v| v.as_bool()).unwrap_or(true),
                                    "kill_switch": prefs.get("kill_switch").and_then(|v| v.as_bool()).unwrap_or(false),
                                }))
                                .send();
                            if let Err(e) = result {
                                let _ = notify
                                    .notification()
                                    .builder()
                                    .title("Burrow VPN")
                                    .body(&format!("Failed to connect: {e}"))
                                    .show();
                            }
                        });
                    }
                    "disconnect" => {
                        let notify = app.clone();
                        thread::spawn(move || {
                            let client = reqwest::blocking::Client::builder()
                                .timeout(std::time::Duration::from_secs(10))
                                .build()
                                .expect("HTTP client init failed");
                            let result = client
                                .post("http://127.0.0.1:9090/api/disconnect")
                                .send();
                            if let Err(e) = result {
                                let _ = notify
                                    .notification()
                                    .builder()
                                    .title("Burrow VPN")
                                    .body(&format!("Failed to disconnect: {e}"))
                                    .show();
                            }
                        });
                    }
                    "quit" => {
                        kill_daemon(app);
                        app.exit(0);
                    }
                    _ => {}
                });

                tray.on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { .. } = event {
                        show_window(tray.app_handle());
                    }
                });

                let tray_handle = app.tray_by_id("main").unwrap();
                let notify_handle = app.handle().clone();
                thread::spawn(move || {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(Duration::from_secs(3))
                        .build()
                        .expect("HTTP client init failed");
                    let mut was_connected = false;
                    loop {
                        if SHUTDOWN.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(3));
                        if SHUTDOWN.load(Ordering::Relaxed) {
                            break;
                        }
                        let status = client
                            .get("http://127.0.0.1:9090/api/status")
                            .send()
                            .and_then(|r| r.json::<serde_json::Value>());
                        let (connected, server_name) = match &status {
                            Ok(v) => {
                                let running =
                                    v.get("running").and_then(|r| r.as_bool()).unwrap_or(false);
                                let server = v
                                    .get("server")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                (running, server)
                            }
                            Err(_) => (false, String::new()),
                        };
                        if connected != was_connected {
                            if SHUTDOWN.load(Ordering::Relaxed) {
                                break;
                            }

                            let tooltip = if connected {
                                "Burrow VPN — Connected"
                            } else {
                                "Burrow VPN — Disconnected"
                            };
                            let _ = tray_handle.set_tooltip(Some(tooltip));

                            let _ = connect_item.set_enabled(!connected);
                            let _ = disconnect_item.set_enabled(connected);
                            if connected {
                                let label = if server_name.is_empty() {
                                    "Disconnect".to_string()
                                } else {
                                    format!("Disconnect ({})", server_name)
                                };
                                let _ = disconnect_item.set_text(&label);
                            } else {
                                let _ = disconnect_item.set_text("Disconnect");
                            }

                            let body = if connected {
                                if server_name.is_empty() {
                                    "Connected".to_string()
                                } else {
                                    format!("Connected to {server_name}")
                                }
                            } else if status.is_err() {
                                "Connection failed".to_string()
                            } else {
                                "Disconnected".to_string()
                            };
                            notify_handle
                                .notification()
                                .builder()
                                .title("Burrow VPN")
                                .body(&body)
                                .show()
                                .unwrap_or_default();

                            was_connected = connected;
                        }
                    }
                });
            }

            // Close-to-tray behavior (desktop only)
            #[cfg(desktop)]
            {
                let window_clone = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_clone.hide();
                    }
                });
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::ExitRequested { .. } = &event {
            SHUTDOWN.store(true, Ordering::Relaxed);
            #[cfg(desktop)]
            kill_daemon(app_handle);
            #[cfg(mobile)]
            let _ = app_handle;
        }
    });
}
