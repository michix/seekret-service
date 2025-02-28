use actix_web::http::StatusCode;
use actix_web::{
    get,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use chrono::{Duration, Utc};
use clap::Parser;
use core::panic;
use keepass::{db::NodeRef, error::DatabaseOpenError, Database, DatabaseKey};
use log::{debug, info};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
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

const KEY_USERNAME: &str = "USN";
const KEY_PASSWORD: &str = "PWD";

static RESETCACHE: Mutex<bool> = Mutex::new(false);

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
    port: u32,
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
}

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

    debug!("Watching file {:?}", keepass_path);

    thread::spawn(|| {
        if let Err(error) = watch(keepass_path) {
            log::error!("Error: {error:?}");
        }
    });

    let _result = run_webservice(config);
    debug!("Webservice started!");
}

#[actix_web::main]
async fn run_webservice(state: Config) -> io::Result<()> {
    let port = state.port.to_string();
    info!("{}", format!("Starting secret service on port {}", port));
    HttpServer::new(move || {
        App::new()
            .service(get_secret)
            .service(get_username)
            .app_data(Data::new(state.clone()))
    })
    .bind(format!("127.0.0.1:{}", port))?
    .workers(1)
    .client_request_timeout(std::time::Duration::new(60, 0))
    .run()
    .await
}

thread_local! {
    static LAST_USER_ACCESS: Cell<chrono::DateTime<Utc>> = Cell::new(Utc::now() - Duration::hours(1));
    static LAST_KEEPASS_ACCESS: Cell<chrono::DateTime<Utc>> = Cell::new(Utc::now() - Duration::weeks(1));
    static SECRETS_MAP: RefCell<HashMap<String, HashMap<String, String>>> = RefCell::new(HashMap::new());
}

fn empty_keepass_cache() {
    debug!("Emptying KeePass cache...");
    SECRETS_MAP.set(HashMap::new());
    let mut guard = RESETCACHE.lock().unwrap();
    let _ = mem::replace(&mut *guard, false);
}

fn get_entry_from_keepass_cache(
    entry_path: &String,
    config: &Config,
) -> Option<HashMap<String, String>> {
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
    let mut values: Option<HashMap<String, String>> = None;
    if secrets_map.contains_key(entry_path) {
        values = Some(secrets_map.get(entry_path).unwrap().clone());
    }
    SECRETS_MAP.set(secrets_map.clone());
    LAST_KEEPASS_ACCESS.set(Utc::now());
    values
}

fn fill_keepass_cache(
    config: &Config,
) -> Result<HashMap<String, HashMap<String, String>>, DatabaseOpenError> {
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

fn db_to_map(db: Database) -> HashMap<String, HashMap<String, String>> {
    let mut map: HashMap<String, HashMap<String, String>> = HashMap::new();
    for node in &db.root.children {
        match node.into() {
            NodeRef::Group(group) => {
                map = recurse_db(group, map, "".to_string());
            }
            NodeRef::Entry(e) => {
                insert_map_values(e, "".into(), &mut map);
            }
        }
    }

    map
}

fn insert_map_values(
    e: &keepass::db::Entry,
    prefix: String,
    map: &mut HashMap<String, HashMap<String, String>>,
) {
    let key: String = prefix.clone() + e.get_title().unwrap_or("(not_title)");
    let password = e.get_password().unwrap_or("(no_password)").into();
    let username = e.get_username().unwrap_or("(no_username)").into();
    debug!("Adding entry: {}", key);
    let mut value_map: HashMap<String, String> = HashMap::new();
    value_map.insert(KEY_USERNAME.into(), username);
    value_map.insert(KEY_PASSWORD.into(), password);
    map.insert(key, value_map);
}

fn recurse_db(
    group: &keepass::db::Group,
    mut map: HashMap<String, HashMap<String, String>>,
    upper_prefix: String,
) -> HashMap<String, HashMap<String, String>> {
    debug!(
        "Entering group '{}' with prefix '{}'...",
        group.name, upper_prefix
    );
    let prefix = upper_prefix + &group.name + "/";
    debug!("Got new prefix: {}", prefix);
    for node in &group.children {
        match node.into() {
            NodeRef::Group(group) => {
                map = recurse_db(group, map.clone(), prefix.clone());
            }
            NodeRef::Entry(e) => {
                insert_map_values(e, prefix.clone(), &mut map);
            }
        }
    }
    map
}

#[cfg(target_os = "linux")]
fn get_password_from_user() -> String {
    debug!("Querying user for password...");
    let mut get_password = Command::new("zenity");
    get_password
        .arg("--password")
        .arg("--title")
        .arg("Secret Service");
    let password = get_password.output().expect("Password not provided");
    str::trim(str::from_utf8(&password.stdout).unwrap()).into()
}

#[cfg(target_os = "macos")]
fn get_password_from_user() -> String {
    debug!("Querying user for password...");
    let mut get_password = Command::new("osascript");
    get_password.arg("-e").arg("Tell application \"System Events\" to display dialog \"Please provide the password for your safe:\" with hidden answer default answer \"\"").arg("-e").arg("text returned of result");
    let password = get_password.output().expect("Password not provided");
    str::trim(str::from_utf8(&password.stdout).unwrap()).into()
}

#[cfg(target_os = "windows")]
fn get_password_from_user() -> String {
    debug!("Querying user for password...");
    let password_window = &PasswordWindow::new("Please provide a password".to_owned());
    let result = password_window.run();
    match result {
        Ok(value) => value,
        Err(_e) => "".to_owned(),
    }
}

fn get_user_authorization(config: &Config) -> bool {
    let mut authorization_given = true;
    // Only ask if the user has now acknowledged recently
    if LAST_USER_ACCESS.get().timestamp_millis()
        < (Utc::now() - Duration::seconds(config.timeout_authorization_in_seconds))
            .timestamp_millis()
    {
        if config.use_touch_id {
            authorization_given = user_authorization_dialog_touchid();
        } else {
            authorization_given = user_authorization_dialog_basic();
        }
    }
    if authorization_given {
        LAST_USER_ACCESS.set(Utc::now());
    }
    authorization_given
}

#[cfg(target_os = "macos")]
fn user_authorization_dialog_touchid() -> bool {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, Policy, PolicyBuilder, Text, WindowsText,
    };

    let policy: Policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .watch(true)
        .build()
        .unwrap();

    let text = Text {
        android: AndroidText {
            title: "Authorize access to Secret Service",
            subtitle: Some("Please authorize access to Secret Service which has been requested."),
            description: Some(
                "Please authorize access to Secret Service which has been requested.",
            ),
        },
        apple: "Authorize access to Secret Service",
        windows: WindowsText::new(
            "Authorize access to Secret Service",
            "Please authorize access to Secret Service which has been requested.",
        )
        .expect("Cannot create Windows Text"),
    };

    Context::new(())
        .blocking_authenticate(text, &policy)
        .expect("Authentication failed");
    true
}

#[cfg(target_os = "windows")]
fn user_authorization_dialog_touchid() -> bool {
    user_authorization_dialog_basic()
}

#[cfg(target_os = "linux")]
fn user_authorization_dialog_touchid() -> bool {
    user_authorization_dialog_basic()
}

#[cfg(target_os = "linux")]
fn user_authorization_dialog_basic() -> bool {
    debug!("Querying user for authorization...");
    let mut get_autorization = Command::new("zenity");
    get_autorization
        .arg("--question")
        .arg("--text")
        .arg("Do you want to allow access to Secret Service?");
    let result = get_autorization
        .status()
        .expect("Authorization from user aborted");
    result.success()
}

#[cfg(target_os = "macos")]
fn user_authorization_dialog_basic() -> bool {
    debug!("Querying user for authorization...");
    let mut get_autorization = Command::new("osascript");
    get_autorization
        .arg("-e")
        .arg("Tell application \"System Events\" to display dialog \"Please approve access...\"");
    let result = get_autorization
        .status()
        .expect("Authorization from user aborted");
    result.success()
}

#[cfg(target_os = "windows")]
fn user_authorization_dialog_basic() -> bool {
    debug!("Querying user for authorization...");
    let ok_abort_window = &OkAbortWindow::new(
        "SeekretService".to_owned(),
        "Please confirm access to KeePass from SeekretService...".to_owned(),
    );
    let result = ok_abort_window.run();
    debug!("Showed window with");
    match result {
        Ok(_value) => true,
        Err(_value) => false,
    }
}

#[get("/{entry_path:.*}/secret")]
async fn get_secret(path: web::Path<(String,)>, config: web::Data<Config>) -> impl Responder {
    let entry_path = path.into_inner().0.to_string();
    info!("Got request for: {}", entry_path);

    // Request access from user if last authoriation has not been recently
    if !get_user_authorization(config.get_ref()) {
        return HttpResponse::Unauthorized().body("Access denied by user!");
    }

    let secret = get_entry_from_keepass_cache(&entry_path, &config);
    match secret {
        Some(secret_string) => {
            HttpResponse::Ok().body(secret_string.get(KEY_PASSWORD).unwrap().to_string())
        }
        None => HttpResponse::build(StatusCode::NOT_FOUND)
            .body(format!("Failed to retrieve secret for: {}", entry_path)),
    }
}

#[get("/{entry_path:.*}/username")]
async fn get_username(path: web::Path<(String,)>, config: web::Data<Config>) -> impl Responder {
    let entry_path = path.into_inner().0.to_string();
    info!("Got request for: {}", entry_path);

    // Request access from user if last authorization has not been recently
    if !get_user_authorization(config.get_ref()) {
        return HttpResponse::Unauthorized().body("Access denied by user!");
    }

    let username = get_entry_from_keepass_cache(&entry_path, config.get_ref());
    match username {
        Some(secret_string) => {
            HttpResponse::Ok().body(secret_string.get(KEY_USERNAME).unwrap().to_string())
        }
        None => HttpResponse::build(StatusCode::NOT_FOUND)
            .body(format!("Failed to retrieve secret for: {}", entry_path)),
    }
}

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
            Ok(_event) => {
                let mut guard = RESETCACHE.lock().unwrap();
                let _ = mem::replace(&mut *guard, true);
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
}
