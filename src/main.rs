use actix_web::{
    get,
    http::StatusCode,
    web::{self, Data},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chacha20poly1305::Nonce;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use chrono::{Duration, Utc};
use clap::Parser;
use core::panic;
use keepass::{db::NodeRef, error::DatabaseOpenError, Database, DatabaseKey};
use log::{debug, info};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::str;
use std::sync::Mutex;
use std::thread;
use std::{fs::File, path::PathBuf};
use std::{io, mem};

#[cfg(target_os = "windows")]
mod ok_abort_window;
#[cfg(target_os = "windows")]
mod password_window;
#[cfg(target_os = "windows")]
use ok_abort_window::OkAbortWindow;
#[cfg(target_os = "windows")]
use password_window::PasswordWindow;

#[cfg(not(target_os = "windows"))]
mod ssh_agent;

const KEY_USERNAME: &str = "USN";
const KEY_PASSWORD: &str = "PWD";
const KEY_SSH_KEY: &str = "SSH";
const KEY_NONCE: &str = "NON";

static RESETCACHE: Mutex<bool> = Mutex::new(false);

/// Tracks the last time the user authorized access. Shared between HTTP handlers
/// and the SSH agent thread. Initialized to one hour in the past so the first
/// request always requires authorization.
static LAST_USER_ACCESS: Mutex<Option<chrono::DateTime<Utc>>> = Mutex::new(None);

/// Secret service
#[derive(Parser, Clone)]
#[clap(
    author = "Michael Jaeger",
    version,
    about = "Simple webservice for accessing elements from a KeePass database file.\nYou may want to start it in background using the following command: `nohup seekret-service --keepass-path \"/path/to/keepassfile.kdbx\" > /dev/null 2>&1 &`. Then you can access the secret of an entry using `curl http://localhost:8123/path/to/entry/secret` or the username of an entry using `http://localhost:8123/path/to/entry/username`."
)]
pub struct Config {
    /// The keepass filename
    #[arg(long)]
    keepass_path: PathBuf,
    /// The keyfile used for KeePass
    #[arg(long)]
    keepass_keyfile: Option<PathBuf>,
    /// Portnumber under which secret service is access
    #[arg(long, default_value_t = 8123)]
    port: u16,
    /// Number of hours the KeePass database should be kept in memory before asking again for the
    /// password
    #[arg(long, default_value_t = 12)]
    timeout_keepass_cache_in_hours: i64,
    /// Number of seconds in which a subsequent request should be answered without user Authorization
    #[arg(long, default_value_t = 10)]
    timeout_authorization_in_seconds: i64,
    /// Use Touch ID on Mac
    #[arg(long, default_value_t = false)]
    use_touch_id: bool,
    /// Enable SSH agent (Linux/macOS only)
    #[arg(long, default_value_t = false)]
    enable_ssh_agent: bool,
    /// KeePass entry paths containing SSH private keys (repeatable)
    #[arg(long)]
    ssh_key: Vec<String>,
    /// Custom SSH agent socket path (default: $HOME/.seekret-ssh-agent.sock)
    #[arg(long)]
    ssh_agent_sock: Option<PathBuf>,
}

/// Initializes the logger, parses configuration, checks file existence,
/// starts the file watcher thread, and launches the webservice.
///
/// On macOS the main thread is kept free for the CoreFoundation run loop so
/// that GCD main-queue dispatch works for native AppKit dialogs. The Actix
/// webservice is started on a background thread instead. On other platforms
/// the webservice runs on the main thread as before.
fn main() {
    env_logger::init();
    let config = Config::parse();
    let keepass_path = config.clone().keepass_path;

    // Check if keepass-file exists
    if !config.keepass_path.exists() {
        panic!(
            "KeePass file does not exist: {:?}",
            keepass_path.into_os_string().into_string()
        );
    }
    if config.keepass_keyfile.is_some() && !config.keepass_keyfile.clone().unwrap().exists() {
        panic!(
            "KeePass key-file does not exist: {:?}",
            config
                .keepass_keyfile
                .unwrap()
                .into_os_string()
                .into_string()
        );
    }

    debug!("Watching file {}", keepass_path.display());

    thread::spawn(|| {
        if let Err(error) = watch(keepass_path) {
            log::error!("Error: {error:?}");
        }
    });

    // On macOS: initialize NSApplication early so that native dialogs
    // (e.g. the SSH-agent password prompt) can process keyboard events
    // even before the main run loop starts.
    #[cfg(target_os = "macos")]
    init_nsapplication();

    // Start SSH agent if enabled (Linux/macOS only)
    #[cfg(not(target_os = "windows"))]
    if config.enable_ssh_agent && config.ssh_key.is_empty() {
        log::error!("SSH agent enabled but no --ssh-key entries specified");
    }

    if is_port_in_use(config.port) {
        log::error!("Error: Port {} is already in use", config.port);
        return;
    }

    // On macOS: run actix on a background thread and keep the main thread
    // free to execute AppKit dialog closures dispatched from worker threads.
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = std::sync::mpsc::channel::<Box<dyn FnOnce() + Send>>();
        MAIN_THREAD_TX
            .set(tx)
            .expect("MAIN_THREAD_TX already initialized");
        MAIN_THREAD_RX
            .set(std::sync::Mutex::new(rx))
            .expect("MAIN_THREAD_RX already initialized");

        info!("Starting webservice...");
        thread::spawn(move || {
            let _result = run_webservice(config);
            info!("Webservice stopped.");
            std::process::exit(0);
        });

        // Run the CFRunLoop on the main thread. A repeating timer drains
        // the work channel so that AppKit events are processed normally
        // between dispatched closures.
        run_main_run_loop();
    }

    // On non-macOS platforms: run the webservice on the main thread as before.
    #[cfg(not(target_os = "macos"))]
    {
        info!("Starting webservice...");
        let _result = run_webservice(config);
        info!("Webservice stopped.");
    }
}

/// Checks if a TCP port is already used by another process.
///
/// # Arguments
///
/// * `port` - The port number to check.
///
/// # Returns
///
/// `true` if the port is in use, `false` otherwise.
fn is_port_in_use(port: u16) -> bool {
    use std::net::TcpListener;
    let addr = format!("127.0.0.1:{port}");
    TcpListener::bind(addr).is_err()
}

/// Channel for dispatching closures to the main thread on macOS.
///
/// Background threads (actix worker, SSH agent) send boxed closures through
/// this channel. The main thread receives and executes them, which guarantees
/// AppKit operations happen on the correct thread.
#[cfg(target_os = "macos")]
static MAIN_THREAD_TX: std::sync::OnceLock<std::sync::mpsc::Sender<Box<dyn FnOnce() + Send>>> =
    std::sync::OnceLock::new();

/// Receiver end of the main-thread work channel.
///
/// Wrapped in a `Mutex` so it can be stored in a static and accessed from the
/// `CFRunLoop` timer callback.
#[cfg(target_os = "macos")]
static MAIN_THREAD_RX: std::sync::OnceLock<
    std::sync::Mutex<std::sync::mpsc::Receiver<Box<dyn FnOnce() + Send>>>,
> = std::sync::OnceLock::new();

/// Installs a minimal main menu with an Edit menu on MacOS.
///
/// This function is a workaround to enable standard keyboard shortcuts
/// (such as <kbd>Command+V</kbd> for paste) in password input fields,
/// which require an Edit menu to be present in the application menu bar.
///
/// # Arguments
///
/// * `mtm` - The `MainThreadMarker` required for AppKit operations.
///
/// # Platform
///
/// Only available on MacOS (`#[cfg(target_os = "macos")]`).
///
/// # Safety
///
/// This function performs unsafe operations with the Objective-C runtime.
///
/// # Implementation Notes
///
/// - Does nothing if a main menu already exists.
/// - Adds an application menu (required by AppKit) and an Edit menu with
///   standard items: Cut, Copy, Paste, Select All, Undo.
/// - Each menu item is bound to the corresponding selector and key equivalent.
///
/// # Hack
///
/// This is a hack to work around the lack of default Edit menu in custom
/// password dialogs, ensuring that Command-based shortcuts work as expected.
///
/// # Example
///
/// ```rust
/// #[cfg(target_os = "macos")]
/// install_edit_menu(mtm);
/// ```
#[cfg(target_os = "macos")]
fn install_edit_menu(mtm: objc2_foundation::MainThreadMarker) {
    use objc2_app_kit::{NSApplication, NSMenu, NSMenuItem};
    use objc2_foundation::NSString;
    unsafe {
        let app = NSApplication::sharedApplication(mtm);
        // Do nothing if a main menu already exists
        if app.mainMenu().is_some() {
            return;
        }
        let main_menu = NSMenu::new(mtm);
        // Slot 0: application menu (required by AppKit)
        let app_item = NSMenuItem::new(mtm);
        main_menu.addItem(&app_item);
        let app_menu = NSMenu::new(mtm);
        app_item.setSubmenu(Some(&app_menu));
        // Edit menu
        let edit_item = NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &NSString::from_str("Edit"),
            None,
            &NSString::from_str(""),
        );
        main_menu.addItem(&edit_item);
        let edit_menu = NSMenu::initWithTitle(mtm.alloc(), &NSString::from_str("Edit"));
        edit_item.setSubmenu(Some(&edit_menu));
        for (title, sel_name, key) in [
            ("Cut",        "cut:",       "x"),
            ("Copy",       "copy:",      "c"),
            ("Paste",      "paste:",     "v"),
            ("Select All", "selectAll:", "a"),
            ("Undo",       "undo:",      "z"),
        ] {
            let sel = objc2::runtime::Sel::register(sel_name);
            let item = NSMenuItem::initWithTitle_action_keyEquivalent(
                mtm.alloc(),
                &NSString::from_str(title),
                Some(sel),
                &NSString::from_str(key),
            );
            edit_menu.addItem(&item);
        }
        app.setMainMenu(Some(&main_menu));
    }
}

/// Initializes NSApplication with the Accessory activation policy.
///
/// Must be called on the main thread before entering CFRunLoopRun so that
/// AppKit is ready when dialogs are dispatched to the main thread later.
#[cfg(target_os = "macos")]
fn init_nsapplication() {
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
    use objc2_foundation::MainThreadMarker;

    // SAFETY: Called from the main thread during startup before CFRunLoopRun.
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    install_edit_menu(mtm);
}

/// Runs the main thread run loop on macOS, draining work items from the
/// channel while keeping AppKit's event processing alive.
///
/// Uses the standard NSApplication event pump so that AppKit events
/// (window close, redraw, etc.) are fully processed between work items.
#[cfg(target_os = "macos")]
fn run_main_run_loop() {
    use objc2_app_kit::{NSApplication, NSEventMask};
    use objc2_foundation::{MainThreadMarker, NSDefaultRunLoopMode};

    // SAFETY: Called from the main thread during startup.
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = NSApplication::sharedApplication(mtm);

    loop {
        // Pump all pending AppKit events.
        loop {
            let event = unsafe {
                app.nextEventMatchingMask_untilDate_inMode_dequeue(
                    NSEventMask::Any,
                    None, // don't wait — return immediately if no events
                    NSDefaultRunLoopMode,
                    true,
                )
            };
            match event {
                Some(e) => unsafe { app.sendEvent(&e) },
                None => break,
            }
        }

        // Take one pending work item if available.
        let work = MAIN_THREAD_RX.get().and_then(|rx_lock| {
            let rx = rx_lock.try_lock().ok()?;
            rx.try_recv().ok()
        });
        // Lock is released here. Execute outside the lock so that work()
        // (which may call runModal and pump events) does not deadlock.
        if let Some(w) = work {
            w();
            continue; // Check for more work / events immediately.
        }

        // No work and no events — sleep briefly to avoid busy-waiting.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Runs the Actix webservice using the provided configuration.
///
/// Creates its own actix runtime so it can run on any thread (main or
/// background). On macOS the webservice runs on a background thread
/// while the main thread stays in CFRunLoopRun for AppKit dialog support.
///
/// If the SSH agent is enabled, its thread is spawned after the HTTP server
/// is bound so that the agent can immediately fetch keys from the API.
///
/// # Arguments
///
/// * `state` - The application configuration.
///
/// # Returns
///
/// An `io::Result<()>` indicating success or failure.
fn run_webservice(state: Config) -> io::Result<()> {
    actix_web::rt::System::new().block_on(async move {
        let port = state.port;
        let port_str = port.to_string();
        info!("Starting secret service on port {port_str}");

        // Extract SSH agent config before moving state into the closure
        #[cfg(not(target_os = "windows"))]
        let ssh_agent_config = if state.enable_ssh_agent && !state.ssh_key.is_empty() {
            let agent_socket = state.ssh_agent_sock.clone().unwrap_or_else(|| {
                let home = std::env::var("HOME").expect("HOME environment variable is not set");
                PathBuf::from(format!("{home}/.seekret-ssh-agent.sock"))
            });
            Some((state.ssh_key.clone(), agent_socket))
        } else {
            None
        };

        let server = HttpServer::new(move || {
            App::new()
                .service(get_secret)
                .service(get_username)
                .service(get_ssh_key)
                .app_data(Data::new(state.clone()))
        })
        .bind(format!("127.0.0.1:{port_str}"))?
        .workers(1)
        .client_request_timeout(std::time::Duration::new(60, 0))
        .run();

        // Start SSH agent thread now that the HTTP server is bound and ready
        #[cfg(not(target_os = "windows"))]
        if let Some((entry_paths, agent_socket)) = ssh_agent_config {
            thread::spawn(move || {
                ssh_agent::run_agent(port, entry_paths, agent_socket);
            });
        }

        server.await
    })
}

thread_local! {
    static LAST_KEEPASS_ACCESS: Cell<chrono::DateTime<Utc>> = Cell::new(Utc::now() - Duration::weeks(1));
    static SECRETS_MAP: RefCell<HashMap<String, HashMap<String, Vec<u8>>>> = RefCell::new(HashMap::new());
    static CIPHER: RefCell<ChaCha20Poly1305> = RefCell::new(ChaCha20Poly1305::new(&ChaCha20Poly1305::generate_key(&mut OsRng)));
}

/// Empties the KeePass cache and resets the cache invalidation flag.
fn empty_keepass_cache() {
    debug!("Emptying KeePass cache...");
    SECRETS_MAP.set(HashMap::new());
    let mut guard = RESETCACHE.lock().unwrap();
    let _ = mem::replace(&mut *guard, false);
}

/// Retrieves an entry from the KeePass cache, refreshing the cache if needed.
///
/// # Arguments
///
/// * `entry_path` - The path to the KeePass entry.
/// * `config` - The application configuration.
///
/// # Returns
///
/// An `Option` containing the entry's secret map if found.
fn get_entry_from_keepass_cache(
    entry_path: &String,
    config: &Config,
) -> Option<HashMap<String, Vec<u8>>> {
    debug!("Obtaining secret '{}' from KeePass cache...", entry_path);
    let reset_cache = RESETCACHE.lock().unwrap().to_owned();
    // Check if last access is too long ago
    if reset_cache
        || LAST_KEEPASS_ACCESS.get().timestamp_millis()
            < (Utc::now() - Duration::hours(config.timeout_keepass_cache_in_hours))
                .timestamp_millis()
    {
        debug!("Resetting KeePass cache because of timeout");
        empty_keepass_cache();
    }
    let mut secrets_map = SECRETS_MAP.take();
    if secrets_map.is_empty() {
        secrets_map = fill_keepass_cache(config).expect("Filling KeePass cache failed");
    }
    let mut values: Option<HashMap<String, Vec<u8>>> = None;
    if secrets_map.contains_key(entry_path) {
        values = Some(secrets_map.get(entry_path).unwrap().clone());
    }
    SECRETS_MAP.set(secrets_map.clone());
    LAST_KEEPASS_ACCESS.set(Utc::now());
    values
}

/// Fills the KeePass cache by opening the database and extracting entries.
///
/// # Arguments
///
/// * `config` - The application configuration.
///
/// # Returns
///
/// A `Result` containing the map of entries or a database open error.
fn fill_keepass_cache(
    config: &Config,
) -> Result<HashMap<String, HashMap<String, Vec<u8>>>, DatabaseOpenError> {
    let keepass_path = config.keepass_path.clone();
    debug!(
        "Filling KeePass cache with KeePass database from file '{}'...",
        keepass_path.to_str().expect("Filename not provided")
    );

    let password = get_password_from_user();
    debug!("Password has length: {}", password.len());
    let mut keepass_db_file = File::open(keepass_path).expect("KeePass DB file not found");
    let mut key = DatabaseKey::new().with_password(&password);
    if config.keepass_keyfile.is_some() {
        let mut keepass_key_file = File::open(config.keepass_keyfile.as_ref().unwrap())
            .expect("KeePass key file not found");
        key = key
            .with_keyfile(&mut keepass_key_file)
            .expect("Failed to open KeePass key file");
    }
    debug!("Opening KeePass database..");
    let db = Database::open(&mut keepass_db_file, key).expect("Failed to open database");
    let password_map = db_to_map(db);

    debug!("Got {} entries in cache.", password_map.keys().len());

    Ok(password_map)
}

/// Converts a KeePass database into a map of entry paths to secret maps.
///
/// # Arguments
///
/// * `db` - The KeePass database.
///
/// # Returns
///
/// A map of entry paths to their associated secrets.
fn db_to_map(db: Database) -> HashMap<String, HashMap<String, Vec<u8>>> {
    let mut map: HashMap<String, HashMap<String, Vec<u8>>> = HashMap::new();
    for node in &db.root.children {
        match node.into() {
            NodeRef::Group(group) => {
                recurse_db(group, &mut map, "");
            }
            NodeRef::Entry(e) => {
                insert_map_values(e, "".into(), &mut map);
            }
        }
    }

    map
}

/// Inserts the values of a KeePass entry into the provided map, encrypting them.
///
/// # Arguments
///
/// * `e` - The KeePass entry.
/// * `prefix` - The path prefix for the entry.
/// * `map` - The map to insert the entry into.
fn insert_map_values(
    e: &keepass::db::Entry,
    prefix: String,
    map: &mut HashMap<String, HashMap<String, Vec<u8>>>,
) {
    let key: String = prefix.clone() + e.get_title().unwrap_or("(not_title)");
    let cipher = CIPHER.with(|c| c.borrow().clone());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let password = cipher
        .encrypt(
            &nonce,
            e.get_password().unwrap_or("(no_password)").as_bytes(),
        )
        .expect("Failed to encrypt password");
    let username = cipher
        .encrypt(
            &nonce,
            e.get_username().unwrap_or("(no_username)").as_bytes(),
        )
        .expect("Failed to encrypt username");
    debug!("Adding entry: {}", key);
    let mut value_map: HashMap<String, Vec<u8>> = HashMap::new();
    value_map.insert(KEY_USERNAME.into(), username);
    value_map.insert(KEY_PASSWORD.into(), password);
    // Store the ssh-key custom field if present
    if let Some(ssh_key_pem) = e.get("ssh-key") {
        if !ssh_key_pem.is_empty() {
            let encrypted_ssh_key = cipher
                .encrypt(&nonce, ssh_key_pem.as_bytes())
                .expect("Failed to encrypt ssh-key");
            value_map.insert(KEY_SSH_KEY.into(), encrypted_ssh_key);
        }
    }
    value_map.insert(KEY_NONCE.into(), nonce.to_vec());
    map.insert(key, value_map);
}

/// Recursively traverses a KeePass group and inserts its entries into the map.
///
/// # Arguments
///
/// * `group` - The KeePass group.
/// * `map` - The map to insert entries into.
/// * `upper_prefix` - The path prefix for the group.
///
/// # Returns
///
/// The updated map with entries from the group.
fn recurse_db(
    group: &keepass::db::Group,
    map: &mut HashMap<String, HashMap<String, Vec<u8>>>,
    upper_prefix: &str,
) {
    let prefix = format!("{}{}/", upper_prefix, group.name);
    debug!(
        "Entering group '{}' with prefix '{}'...",
        group.name, prefix
    );
    for node in &group.children {
        match node.into() {
            NodeRef::Group(g) => {
                recurse_db(g, map, &prefix);
            }
            NodeRef::Entry(e) => {
                insert_map_values(e, prefix.clone(), map);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn get_password_from_user() -> String {
    debug!("Querying user for password...");
    let mut get_password = Command::new("zenity");
    get_password
        .arg("--password")
        .arg("--title")
        .arg(format!("Seekret Service {}", env!("CARGO_PKG_VERSION")));
    let password = get_password.output().expect("Password not provided");
    str::trim(str::from_utf8(&password.stdout).unwrap()).into()
}

/// Executes a closure on the macOS main thread, blocking until complete.
///
/// AppKit UI operations (e.g. `NSAlert::runModal`) must run on the main thread.
/// This helper sends the work to the main thread via a channel when called from
/// a background thread (e.g. an actix worker or the SSH-agent thread), and calls
/// the closure directly when already on the main thread (e.g. during startup).
///
/// # Arguments
///
/// * `f` - The closure to execute on the main thread.
///
/// # Returns
///
/// The return value of the closure.
#[cfg(target_os = "macos")]
fn run_on_main_thread<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    use objc2_foundation::NSThread;
    if NSThread::isMainThread_class() {
        f()
    } else {
        // Use a channel pair so the calling thread blocks until the main
        // thread has finished executing the closure and sent back the result.
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let work = Box::new(move || {
            let val = f();
            let _ = result_tx.send(val);
        });
        MAIN_THREAD_TX
            .get()
            .expect("MAIN_THREAD_TX not initialized")
            .send(work)
            .expect("Main thread channel closed");
        result_rx.recv().expect("Main thread did not send result")
    }
}

/// Queries the user for the KeePass database password using a native macOS dialog.
///
/// Uses NSAlert with an NSSecureTextField accessory view to display
/// a native password input dialog with masked text entry.
///
/// # Returns
///
/// The password entered by the user, or an empty string if cancelled.
#[cfg(target_os = "macos")]
pub(crate) fn get_password_from_user() -> String {
    debug!("Querying user for password...");

    run_on_main_thread(|| {
        use objc2::msg_send;
        use objc2::sel;
        use objc2_app_kit::{
            NSAlert, NSAlertFirstButtonReturn, NSApplication, NSApplicationActivationOptions,
            NSRunningApplication, NSSecureTextField, NSWorkspace,
        };
        use objc2_foundation::{MainThreadMarker, NSString};

        // SAFETY: Guaranteed to be on the main thread by run_on_main_thread.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let app = NSApplication::sharedApplication(mtm);

        // Remember which application had focus so we can restore it after the
        // dialog is dismissed.
        let previous_app: Option<objc2::rc::Retained<NSRunningApplication>> =
            unsafe { NSWorkspace::sharedWorkspace().frontmostApplication() };

        // Bring the process to the front so the dialog is visible.
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let result = unsafe {
            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&format!(
                "Seekret Service {}",
                env!("CARGO_PKG_VERSION")
            )));
            alert.setInformativeText(&NSString::from_str(
                "Please provide the password for your safe:",
            ));

            let input = NSSecureTextField::initWithFrame(
                mtm.alloc(),
                objc2_foundation::NSRect::new(
                    objc2_foundation::NSPoint::new(0.0, 0.0),
                    objc2_foundation::NSSize::new(300.0, 24.0),
                ),
            );
            input.setBezeled(true);
            input.setEditable(true);

            // Wire the text field so that pressing Return triggers the alert's
            // OK button.  When NSTextField sends its action (on Return), the
            // field editor commits typed text to stringValue first, then fires
            // performClick: on the OK button which ends the modal session.
            let buttons = alert.buttons();
            let ok_button = &buttons[0];
            input.setTarget(Some(ok_button));
            input.setAction(Some(sel!(performClick:)));

            alert.setAccessoryView(Some(input.as_ref()));

            // Force the alert to lay out its view hierarchy, then tell the
            // window which view should receive initial keyboard focus.
            alert.layout();
            let window = alert.window();
            let input_ref: &NSSecureTextField = &input;
            let _: () = msg_send![&window, setInitialFirstResponder: input_ref];
            let _: bool = msg_send![input_ref, becomeFirstResponder];

            let response = alert.runModal();
            if response == NSAlertFirstButtonReturn {
                String::new()
            } else {
                input.stringValue().to_string()
            }
        };

        // Restore focus to the application that was active before the dialog.
        if let Some(prev) = previous_app {
            #[allow(deprecated)]
            unsafe {
                prev.activateWithOptions(
                    NSApplicationActivationOptions::NSApplicationActivateIgnoringOtherApps,
                );
            }
        }

        result
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn get_password_from_user() -> String {
    debug!("Querying user for password...");
    let password_window = &PasswordWindow::new(format!(
        "Seekret Service {}: Please enter password",
        env!("CARGO_PKG_VERSION")
    ));
    let result = password_window.run();
    match result {
        Ok(value) => value,
        Err(_e) => "".to_owned(),
    }
}

/// Requests user authorization, using Touch ID or a basic dialog as configured.
///
/// # Arguments
///
/// * `config` - The application configuration.
/// * `source` - An optional string describing the source of the request,
///              displayed in the authorization dialog.
///
/// # Returns
///
/// `true` if authorization is granted, `false` otherwise.
fn get_user_authorization(config: &Config, source: Option<&str>) -> bool {
    let mut authorization_given = true;
    // Only ask if the user has not acknowledged recently
    let needs_auth = {
        let last_access = LAST_USER_ACCESS.lock().unwrap();
        match *last_access {
            None => true,
            Some(ts) => {
                ts.timestamp_millis()
                    < (Utc::now() - Duration::seconds(config.timeout_authorization_in_seconds))
                        .timestamp_millis()
            }
        }
    };
    if needs_auth {
        if config.use_touch_id {
            authorization_given = user_authorization_dialog_touchid(source);
        } else {
            authorization_given = user_authorization_dialog_basic(source);
        }
    }
    if authorization_given {
        let mut last_access = LAST_USER_ACCESS.lock().unwrap();
        *last_access = Some(Utc::now());
    }
    authorization_given
}

#[cfg(target_os = "macos")]
pub(crate) fn user_authorization_dialog_touchid(source: Option<&str>) -> bool {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, Policy, PolicyBuilder, Text, WindowsText,
    };

    let policy: Policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .watch(true)
        .build()
        .unwrap();

    let title = format!("Seekret Service {}", env!("CARGO_PKG_VERSION"));
    let subtitle = match source {
        Some(s) => format!(
            "Please authorize access to Secret Service which has been requested.\n\nRequested by: {s}"
        ),
        None => {
            "Please authorize access to Secret Service which has been requested.".to_owned()
        }
    };
    let text = Text {
        android: AndroidText {
            title: &title,
            subtitle: Some(&subtitle),
            description: Some(&subtitle),
        },
        apple: &title,
        windows: WindowsText::new(&title, &subtitle)
            .expect("Cannot create Windows Text"),
    };

    // Remember the frontmost application so focus can be restored afterward.
    // NSRunningApplication is not Send, so we carry the raw pointer as a usize
    // and only dereference it back on the main thread.
    let previous_app_ptr: usize = run_on_main_thread(|| {
        use objc2::rc::Retained;
        use objc2_app_kit::NSRunningApplication;
        use objc2_app_kit::NSWorkspace;
        let app: Option<Retained<NSRunningApplication>> =
            unsafe { NSWorkspace::sharedWorkspace().frontmostApplication() };
        match app {
            Some(a) => Retained::into_raw(a) as usize,
            None => 0,
        }
    });

    Context::new(())
        .blocking_authenticate(text, &policy)
        .expect("Authentication failed");

    // Restore focus to the application that was active before the dialog.
    if previous_app_ptr != 0 {
        run_on_main_thread(move || {
            use objc2::rc::Retained;
            use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication};
            // SAFETY: The pointer was obtained from Retained::into_raw on the
            // main thread above.  We reconstitute ownership here, also on the
            // main thread, exactly once.
            let prev: Retained<NSRunningApplication> = unsafe {
                Retained::from_raw(previous_app_ptr as *mut NSRunningApplication)
                    .expect("NSRunningApplication pointer was null")
            };
            #[allow(deprecated)]
            unsafe {
                prev.activateWithOptions(
                    NSApplicationActivationOptions::NSApplicationActivateIgnoringOtherApps,
                );
            }
        });
    }

    true
}

#[cfg(target_os = "windows")]
pub(crate) fn user_authorization_dialog_touchid(source: Option<&str>) -> bool {
    user_authorization_dialog_basic(source)
}

#[cfg(target_os = "linux")]
pub(crate) fn user_authorization_dialog_touchid(source: Option<&str>) -> bool {
    user_authorization_dialog_basic(source)
}

#[cfg(target_os = "linux")]
pub(crate) fn user_authorization_dialog_basic(source: Option<&str>) -> bool {
    debug!("Querying user for authorization...");
    let text = match source {
        Some(s) => format!("Do you want to allow access to Secret Service?\n\nRequested by: {s}"),
        None => "Do you want to allow access to Secret Service?".to_owned(),
    };
    let mut get_autorization = Command::new("zenity");
    get_autorization
        .arg("--question")
        .arg("--title")
        .arg(format!("Seekret Service {}", env!("CARGO_PKG_VERSION")))
        .arg("--text")
        .arg(text);
    let result = get_autorization
        .status()
        .expect("Authorization from user aborted");
    result.success()
}

/// Displays a native macOS confirmation dialog asking the user to approve access.
///
/// Uses NSAlert with OK and Cancel buttons to present a native confirmation dialog.
///
/// # Arguments
///
/// * `source` - An optional string describing the source of the request.
///
/// # Returns
///
/// `true` if the user clicks OK, `false` if cancelled.
#[cfg(target_os = "macos")]
pub(crate) fn user_authorization_dialog_basic(source: Option<&str>) -> bool {
    debug!("Querying user for authorization...");
    let informative_text = match source {
        Some(s) => format!("Please approve access...\n\nRequested by: {s}"),
        None => "Please approve access...".to_owned(),
    };

    run_on_main_thread(move || {
        use objc2_app_kit::{
            NSAlert, NSAlertFirstButtonReturn, NSAlertStyle, NSApplication,
            NSApplicationActivationOptions, NSRunningApplication, NSWorkspace,
        };
        use objc2_foundation::{MainThreadMarker, NSString};

        // SAFETY: Guaranteed to be on the main thread by run_on_main_thread.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let app = NSApplication::sharedApplication(mtm);

        // Remember which application had focus so we can restore it after the
        // dialog is dismissed.
        let previous_app: Option<objc2::rc::Retained<NSRunningApplication>> =
            unsafe { NSWorkspace::sharedWorkspace().frontmostApplication() };

        // Bring the process to the front so the dialog is visible.
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let result = unsafe {
            let alert = NSAlert::new(mtm);
            alert.setMessageText(&NSString::from_str(&format!(
                "Seekret Service {}",
                env!("CARGO_PKG_VERSION")
            )));
            alert.setInformativeText(&NSString::from_str(&informative_text));
            alert.setAlertStyle(NSAlertStyle::Informational);
            alert.addButtonWithTitle(&NSString::from_str("OK"));
            alert.addButtonWithTitle(&NSString::from_str("Cancel"));

            let response = alert.runModal();
            response == NSAlertFirstButtonReturn
        };

        // Restore focus to the application that was active before the dialog.
        if let Some(prev) = previous_app {
            #[allow(deprecated)]
            unsafe {
                prev.activateWithOptions(
                    NSApplicationActivationOptions::NSApplicationActivateIgnoringOtherApps,
                );
            }
        }

        result
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn user_authorization_dialog_basic(source: Option<&str>) -> bool {
    debug!("Querying user for authorization...");
    let text = match source {
        Some(s) => format!(
            "Please confirm access to KeePass from SeekretService...\n\nRequested by: {s}"
        ),
        None => "Please confirm access to KeePass from SeekretService...".to_owned(),
    };
    let ok_abort_window = &OkAbortWindow::new(
        format!("Seekret Service {}", env!("CARGO_PKG_VERSION")),
        text,
    );
    let result = ok_abort_window.run();
    debug!("Showed window with");
    match result {
        Ok(_value) => true,
        Err(_value) => false,
    }
}

/// Actix handler for retrieving a secret from the KeePass database.
///
/// # Arguments
///
/// * `path` - The web path containing the entry path.
/// * `config` - The application configuration.
///
/// # Returns
///
/// An HTTP response containing the decrypted secret or an error.
#[get("/{entry_path:.*}/secret")]
async fn get_secret(
    req: HttpRequest,
    path: web::Path<(String,)>,
    config: web::Data<Config>,
) -> impl Responder {
    let entry_path = path.into_inner().0.to_string();
    info!("Got request for: {}", entry_path);

    let source = req
        .headers()
        .get("X-Seekret-Source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // Request access from user if last authoriation has not been recently
    if !get_user_authorization(config.get_ref(), source.as_deref()) {
        return HttpResponse::Unauthorized().body("Access denied by user!");
    }

    let cipher = CIPHER.with(|c| c.borrow().clone());
    let secret_entry = get_entry_from_keepass_cache(&entry_path, &config);
    match secret_entry {
        Some(secret_string) => HttpResponse::Ok().body(
            cipher
                .decrypt(
                    Nonce::from_slice(secret_string.get(KEY_NONCE).unwrap()),
                    secret_string.get(KEY_PASSWORD).unwrap().as_ref(),
                )
                .expect("Failed to decrypt secret"),
        ),
        None => HttpResponse::build(StatusCode::NOT_FOUND)
            .body(format!("Failed to retrieve secret for: {}", entry_path)),
    }
}

/// Actix handler for retrieving a username from the KeePass database.
///
/// # Arguments
///
/// * `path` - The web path containing the entry path.
/// * `config` - The application configuration.
///
/// # Returns
///
/// An HTTP response containing the decrypted username or an error.
#[get("/{entry_path:.*}/username")]
async fn get_username(
    req: HttpRequest,
    path: web::Path<(String,)>,
    config: web::Data<Config>,
) -> impl Responder {
    let entry_path = path.into_inner().0.to_string();
    info!("Got request for: {}", entry_path);

    let source = req
        .headers()
        .get("X-Seekret-Source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // Request access from user if last authoriation has not been recently
    if !get_user_authorization(config.get_ref(), source.as_deref()) {
        return HttpResponse::Unauthorized().body("Access denied by user!");
    }

    let cipher = CIPHER.with(|c| c.borrow().clone());
    let secret_entry = get_entry_from_keepass_cache(&entry_path, &config);
    match secret_entry {
        Some(secret_string) => HttpResponse::Ok().body(
            cipher
                .decrypt(
                    Nonce::from_slice(secret_string.get(KEY_NONCE).unwrap()),
                    secret_string.get(KEY_USERNAME).unwrap().as_ref(),
                )
                .expect("Failed to decrypt username"),
        ),
        None => HttpResponse::build(StatusCode::NOT_FOUND)
            .body(format!("Failed to retrieve secret for: {}", entry_path)),
    }
}

/// Actix handler for retrieving an SSH key from the KeePass database.
///
/// Returns the `ssh-key` custom field (plaintext PEM) for the given entry,
/// or 404 if the entry does not exist or has no `ssh-key` field.
///
/// # Arguments
///
/// * `path` - The web path containing the entry path.
/// * `config` - The application configuration.
///
/// # Returns
///
/// An HTTP response containing the decrypted SSH key PEM or an error.
#[get("/{entry_path:.*}/ssh-key")]
async fn get_ssh_key(
    req: HttpRequest,
    path: web::Path<(String,)>,
    config: web::Data<Config>,
) -> impl Responder {
    let entry_path = path.into_inner().0.to_string();
    info!("Got request for: {entry_path}");

    let source = req
        .headers()
        .get("X-Seekret-Source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    // Request access from user if last authorization has not been recently
    if !get_user_authorization(config.get_ref(), source.as_deref()) {
        return HttpResponse::Unauthorized().body("Access denied by user!");
    }

    let cipher = CIPHER.with(|c| c.borrow().clone());
    let secret_entry = get_entry_from_keepass_cache(&entry_path, &config);
    match secret_entry {
        Some(secret_string) => match secret_string.get(KEY_SSH_KEY) {
            Some(encrypted_ssh_key) => HttpResponse::Ok().body(
                cipher
                    .decrypt(
                        Nonce::from_slice(secret_string.get(KEY_NONCE).unwrap()),
                        encrypted_ssh_key.as_ref(),
                    )
                    .expect("Failed to decrypt ssh-key"),
            ),
            None => HttpResponse::build(StatusCode::NOT_FOUND)
                .body(format!("No ssh-key found for: {entry_path}")),
        },
        None => HttpResponse::build(StatusCode::NOT_FOUND)
            .body(format!("Failed to retrieve secret for: {entry_path}")),
    }
}

/// Watches the specified path for changes and sets a flag to reset the cache on modification.
///
/// # Arguments
///
/// * `path` - The path to watch.
///
/// # Returns
///
/// A `notify::Result<()>` indicating success or failure.
fn watch<P: AsRef<Path>>(path: P) -> notify::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let mut watcher = RecommendedWatcher::new(tx, notify::Config::default())?;

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    for res in rx {
        match res {
            Ok(event) => {
                debug!("File watcher event: {:?}", event);
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        info!(
                            "KeePass file changed ({:?}), flagging cache for reset",
                            event.kind
                        );
                        let mut guard = RESETCACHE.lock().unwrap();
                        let _ = mem::replace(&mut *guard, true);
                    }
                    _ => {
                        debug!("Ignoring non-modification file event: {:?}", event.kind);
                    }
                }
            }
            Err(error) => log::error!("An error occured monitoring the KeePass file: {error:?}"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_log::test]
    fn test_open_keepass_database() {
        let mut db_file = File::open("test.kdbx").expect("File not found");
        let mut key_file = File::open("test.key").expect("Key-file not found");
        let key = DatabaseKey::new()
            .with_password("test")
            .with_keyfile(&mut key_file)
            .expect("Failed to open key-file");
        let db = Database::open(&mut db_file, key).expect("Failed to open database");
        let map = db_to_map(db);
        debug!("Got KeePass map:");
        for key in map.keys() {
            debug!(" - {}", key);
        }
    }

    #[test_log::test]
    fn test_cache_contains_expected_keys() {
        let mut db_file = File::open("test.kdbx").expect("File not found");
        let mut key_file = File::open("test.key").expect("Key-file not found");
        let key = DatabaseKey::new()
            .with_password("test")
            .with_keyfile(&mut key_file)
            .expect("Failed to open key-file");
        let db = Database::open(&mut db_file, key).expect("Failed to open database");
        let map = db_to_map(db);

        // Every entry must have username, password, and nonce
        for (entry_path, value_map) in &map {
            assert!(
                value_map.contains_key(KEY_USERNAME),
                "Entry '{entry_path}' missing username"
            );
            assert!(
                value_map.contains_key(KEY_PASSWORD),
                "Entry '{entry_path}' missing password"
            );
            assert!(
                value_map.contains_key(KEY_NONCE),
                "Entry '{entry_path}' missing nonce"
            );
        }

        // Verify root_entry1 is present and can be decrypted
        let root_entry = map.get("root_entry1").expect("root_entry1 not found");
        let cipher = CIPHER.with(|c| c.borrow().clone());
        let nonce = Nonce::from_slice(root_entry.get(KEY_NONCE).unwrap());
        let decrypted_username = cipher
            .decrypt(nonce, root_entry.get(KEY_USERNAME).unwrap().as_ref())
            .expect("Failed to decrypt username");
        assert_eq!(
            str::from_utf8(&decrypted_username).unwrap(),
            "root-username"
        );
        let decrypted_password = cipher
            .decrypt(nonce, root_entry.get(KEY_PASSWORD).unwrap().as_ref())
            .expect("Failed to decrypt password");
        assert_eq!(
            str::from_utf8(&decrypted_password).unwrap(),
            "root-password"
        );

        // Entries without an ssh-key custom field must not have KEY_SSH_KEY
        // (root_entry1 in the test database has no ssh-key)
        assert!(
            !root_entry.contains_key(KEY_SSH_KEY),
            "root_entry1 should not have an ssh-key entry"
        );
    }

    #[test_log::test]
    fn test_ssh_key_cached_and_decryptable() {
        let mut db_file = File::open("test.kdbx").expect("File not found");
        let mut key_file = File::open("test.key").expect("Key-file not found");
        let key = DatabaseKey::new()
            .with_password("test")
            .with_keyfile(&mut key_file)
            .expect("Failed to open key-file");
        let db = Database::open(&mut db_file, key).expect("Failed to open database");
        let map = db_to_map(db);

        // The test database has an entry 'my-ssh-key' with an ssh-key custom field
        let ssh_entry = map.get("my-ssh-key").expect("my-ssh-key entry not found");
        assert!(
            ssh_entry.contains_key(KEY_SSH_KEY),
            "my-ssh-key should have a cached ssh-key"
        );

        // Verify the ssh-key can be decrypted
        let cipher = CIPHER.with(|c| c.borrow().clone());
        let nonce = Nonce::from_slice(ssh_entry.get(KEY_NONCE).unwrap());
        let decrypted_ssh_key = cipher
            .decrypt(nonce, ssh_entry.get(KEY_SSH_KEY).unwrap().as_ref())
            .expect("Failed to decrypt ssh-key");
        let ssh_key_str = str::from_utf8(&decrypted_ssh_key).expect("ssh-key is not valid UTF-8");
        assert!(
            !ssh_key_str.is_empty(),
            "Decrypted ssh-key should not be empty"
        );
        debug!("Decrypted ssh-key length: {}", ssh_key_str.len());
    }
}
