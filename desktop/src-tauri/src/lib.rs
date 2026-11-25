//! SENTRY desktop shell.
//!
//! Starts the Python SENTRY engine (`sentry serve --print-connection`) as a child process bound to
//! 127.0.0.1, reads the one-time connection line {url, token} from its stdout and hands it to the
//! React UI through the `backend_info` command. The engine is stopped when the app exits.
//! The desktop never performs security actions itself: every action goes through the engine's
//! approval system (approver passphrase, signed single-use approvals).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, RunEvent, State};

#[derive(Clone, Serialize)]
struct Backend {
    url: String,
    token: String,
}

#[derive(Default)]
struct BackendState {
    info: Mutex<Option<Backend>>,
    child: Mutex<Option<Child>>,
    error: Mutex<Option<String>>,
}

fn candidates() -> Vec<(String, Vec<String>)> {
    if let Ok(cmd) = std::env::var("SENTRY_BACKEND") {
        // e.g. SENTRY_BACKEND="C:\path\to\python.exe -m sentry_engine"
        let mut parts = cmd.split_whitespace().map(String::from);
        if let Some(exe) = parts.next() {
            return vec![(exe, parts.collect())];
        }
    }
    let module = vec!["-m".to_string(), "sentry_engine".to_string()];
    vec![
        ("sentry".to_string(), vec![]),
        ("python".to_string(), module.clone()),
        ("py".to_string(), module.clone()),
        ("python3".to_string(), module),
    ]
}

fn spawn_backend() -> Result<(Child, Backend), String> {
    let mut last_error = String::from("no candidate command");
    for (exe, prefix) in candidates() {
        let mut cmd = Command::new(&exe);
        cmd.args(&prefix)
            .args(["serve", "--print-connection"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                last_error = format!("{exe}: {e}");
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            continue;
        };
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(n) if n > 0 => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                    let url = v["url"].as_str().unwrap_or_default().to_string();
                    let token = v["token"].as_str().unwrap_or_default().to_string();
                    if url.starts_with("http://127.0.0.1:") && !token.is_empty() {
                        // keep draining stdout so the engine never blocks on a full pipe
                        std::thread::spawn(move || {
                            let mut sink = String::new();
                            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                                sink.clear();
                            }
                        });
                        return Ok((child, Backend { url, token }));
                    }
                }
                last_error = format!("{exe}: unexpected output from the engine");
            }
            _ => last_error = format!("{exe}: engine exited before it was ready"),
        }
        let _ = child.kill();
    }
    Err(format!(
        "Could not start the SENTRY engine ({last_error}). Install it with `pip install \"sentry-guard[full]\"` \
         or set SENTRY_BACKEND to the command that runs it."
    ))
}

#[tauri::command]
fn backend_info(state: State<'_, BackendState>) -> Result<Backend, String> {
    if let Some(b) = state.info.lock().map_err(|e| e.to_string())?.clone() {
        return Ok(b);
    }
    Err(state
        .error
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .unwrap_or_else(|| "The SENTRY engine is still starting".into()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(BackendState::default())
        .setup(|app| {
            let handle = app.handle().clone();
            // start the engine off the UI thread; the UI polls backend_info until it is ready
            std::thread::spawn(move || {
                let state = handle.state::<BackendState>();
                match spawn_backend() {
                    Ok((child, info)) => {
                        *state.child.lock().unwrap() = Some(child);
                        *state.info.lock().unwrap() = Some(info);
                    }
                    Err(e) => *state.error.lock().unwrap() = Some(e),
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![backend_info])
        .build(tauri::generate_context!())
        .expect("error while building the SENTRY desktop application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(mut child) = app.state::<BackendState>().child.lock().unwrap().take() {
                    let _ = child.kill();
                }
            }
        });
}
