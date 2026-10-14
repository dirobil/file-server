//! Нативное GUI-окно сервера (крейт `eframe`/`egui` — лёгкий immediate-mode UI,
//! без Electron/WebView, в отличие от тяжёлого `tauri`).
//!
//! Окно показывает локальный IP-адрес машины и QR-код на адрес сервера
//! (`http://<ip>:<порт>`): камеру телефона наводят на QR — и открывают страницу
//! загрузки файлов. Рядом — кнопка «Открыть в браузере».
//!
//! Если в конфиге задана директория хранилища, в окне появляется блок с её
//! путём и кнопкой «📂 Открыть папку» (проводник Windows / Finder / xdg-open).
//!
//! Сервер поднимается внутри окна на фоновой tokio-задаче; как только сокет
//! привязан, порт узнаётся через `listener.local_addr()` — поэтому можно
//! стартовать с портом 0 («любой свободный»).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use eframe::egui;

/// Размер QR-картинки в пикселях (рендерим с запасом, на экране масштабируется).
const QR_PIXELS: u32 = 512;

/// Точка входа из `main` при запуске с флагом `--gui`.
/// Разбирает аргументы вида `--bind 0.0.0.0:3000` / `--port 8080`, готовит
/// конфигурацию (тот же конфиг-файл, что и у консольного режима) и запускает
/// окно. Вызывается изнутри `#[tokio::main]`, поэтому блокирующий `eframe`
/// запускаем через `block_in_place`, чтобы не заглушить runtime.
pub fn run_from_cli(args: &[String]) {
    let mut bind = std::env::var("BIND")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "0.0.0.0:3000".to_string());

    // Формы: `--bind=<addr>`, `--bind <addr>`, `--port <n>`
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if let Some(rest) = arg.strip_prefix("--bind=") {
            bind = rest.to_string();
            continue;
        }
        match arg.as_str() {
            "--bind" => {
                if let Some(v) = it.next() {
                    bind = v.clone();
                }
            }
            "--port" => {
                if let Some(v) = it.next() {
                    if let Ok(p) = v.parse::<u16>() {
                        let host = bind.split(':').next().unwrap_or("0.0.0.0").to_string();
                        bind = format!("{host}:{p}");
                    }
                }
            }
            _ => {}
        }
    }

    let (host, port) = split_bind(&bind);

    // Конфиг — тот же файл, что использует консольный режим.
    let config_path = crate::config::config_path();
    let mut cfg = match crate::config::Config::load(&config_path) {
        Ok(Some(c)) => c,
        Ok(None) => crate::config::Config::with_storage(None),
        Err(e) => {
            eprintln!("Предупреждение: {e} — начинаем с чистого конфига");
            crate::config::Config::with_storage(None)
        }
    };
    if !cfg.has_admin_password() {
        if let Ok(pwd) = std::env::var("ADMIN_PASSWORD") {
            cfg.admin.password_hash = crate::auth::hash_password(&pwd);
            if let Err(e) = cfg.save(&config_path) {
                eprintln!("Не удалось сохранить конфиг: {e}");
            }
        }
    }
    if let Some(dir) = std::env::var("STORAGE_DIR").ok().map(PathBuf::from) {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("Не удалось создать директорию {dir:?}: {e}");
            std::process::exit(1);
        }
        if cfg.storage_dir.as_ref() != Some(&dir) {
            cfg.storage_dir = Some(dir);
            if let Err(e) = cfg.save(&config_path) {
                eprintln!("Не удалось сохранить конфиг: {e}");
            }
        }
    }

    let state = crate::state::AppState::new(crate::state::Templates::load(), config_path, cfg);

    let result = tokio::task::block_in_place(|| eframe::run_native(
        "Файловый сервер",
        native_options(),
        Box::new(move |_cc| Ok(Box::new(GuiApp::new(state, host, port))),),
    ));
    if let Err(e) = result {
        eprintln!("Ошибка GUI: {e}");
        std::process::exit(1);
    }
}

fn split_bind(bind: &str) -> (String, u16) {
    match bind.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && let Ok(p) = p.parse::<u16>() => (h.to_string(), p),
        _ => ("0.0.0.0".to_string(), bind.parse().unwrap_or(3000)),
    }
}

fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 560.0])
            .with_min_inner_size([360.0, 420.0])
            .with_title("Файловый сервер"),
        ..Default::default()
    }
}

struct ServerInfo {
    /// URL для QR и кнопки «открыть» — виден из GUI-потока.
    url: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

struct GuiApp {
    state: crate::state::AppState,
    bind_host: String,
    bind_port: u16,
    /// Пакет: сервер + shutdown-канал. Забирается при закрытии окна,
    /// чтобы корректно остановить axum.
    server: Option<ServerInfo>,
    qr_texture: Option<egui::TextureHandle>,
    error: Option<String>,
    /// Сообщение об ошибке последнего действия (открытие папки и т.п.) —
    /// показывается один кадр рядом с соответствующей кнопкой.
    action_error: Option<String>,
}

impl GuiApp {
    fn new(state: crate::state::AppState, bind_host: String, bind_port: u16) -> Self {
        let mut app = Self {
            state,
            bind_host,
            bind_port,
            server: None,
            qr_texture: None,
            error: None,
            action_error: None,
        };
        app.start_server();
        app
    }

    /// Поднимает axum-сервер на отдельном tokio-runtime в фоновом потоке
    /// (GUI-поток блокирующим быть не должен).
    fn start_server(&mut self) {
        self.qr_texture = None;
        let host = self.bind_host.clone();
        let port = self.bind_port;
        let state = self.state.clone();
        let (tx_ready, rx_ready) =
            std::sync::mpsc::channel::<Result<(String, tokio::sync::oneshot::Sender<()>), String>>();
        let (tx_shutdown, rx_shutdown) = tokio::sync::oneshot::channel::<()>();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx_ready.send(Err(format!("не удалось запустить tokio: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind((host.as_str(), port)).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx_ready
                            .send(Err(format!("не удалось привязаться к {host}:{port}: {e}")));
                        return;
                    }
                };
                let bound: SocketAddr = listener.local_addr().unwrap_or_else(|_| {
                    format!("{host}:{port}")
                        .parse()
                        .unwrap_or_else(|_| ([0, 0, 0, 0], port).into())
                });
                let ip = local_ip().unwrap_or(IpAddr::from([127, 0, 0, 1]));
                let url = format!("http://{ip}:{}", bound.port());
                let app = crate::build_router(state);
                let serve = axum::serve(listener, app);
                let _ = tx_ready.send(Ok((url, tx_shutdown)));
                if let Err(e) = tokio::select! {
                    r = serve => r.map_err(|e| e.to_string()),
                    _ = rx_shutdown => Ok(()),
                } {
                    eprintln!("Ошибка сервера: {e}");
                }
            });
        });

        match rx_ready.recv() {
            Ok(Ok((url, shutdown))) => {
                self.server = Some(ServerInfo { url, shutdown });
            }
            Ok(Err(e)) => self.error = Some(e),
            Err(e) => self.error = Some(format!("сервер не запустился: {e}")),
        }
    }

    fn stop_server(&mut self) {
        if let Some(info) = self.server.take() {
            let _ = info.shutdown.send(());
        }
    }

    /// RGBA-пиксели QR-кода для текущего URL (белая рамка-тихая зона обязательна
    /// для надёжного сканирования камерой).
    fn qr_rgba(url: &str) -> Option<(Vec<u8>, [usize; 2])> {
        let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
        // image-рендерер доступен через feature "image" крейта qrcode.
        let img = code
            .render::<image::Luma<u8>>()
            .min_dimensions(QR_PIXELS, QR_PIXELS)
            .build();
        let (w, h) = img.dimensions();
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for &p in img.as_raw() {
            let v = if p == 0 { 0 } else { 255 }; // Luma: 0 = чёрный модуль QR
            rgba.extend_from_slice(&[v, v, v, 255]);
        }
        Some((rgba, [w as usize, h as usize]))
    }

    /// Блок «Папка хранилища»: если в конфиге задана директория — показываем
    /// её путь и кнопку открытия в проводнике ОС. Если не задана — подсказку,
    /// где её настроить (страница /admin).
    fn storage_section(&mut self, ui: &mut egui::Ui) {
        let dir = self.state.storage_dir();
        match dir {
            Some(dir) => {
                let exists = dir.is_dir();
                let path_text = dir.display().to_string();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Хранилище:").strong());
                    let text = if exists {
                        path_text.clone()
                    } else {
                        format!("{path_text} (папка не найдена)")
                    };
                    // Длинные пути троем многоточием, чтобы умещались в окно.
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(text)
                                .monospace()
                                .color(if exists {
                                    egui::Color32::from_rgb(40, 100, 210)
                                } else {
                                    egui::Color32::from_rgb(200, 120, 40)
                                }),
                        )
                        .truncate(),
                    );
                });
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let btn = ui.add_enabled(exists, egui::Button::new("📂 Открыть папку"));
                    if btn.clicked() {
                        // Успех — очищаем предыдущую ошибку; неудача — запоминаем текст.
                        self.action_error = open_path(&dir);
                    } else {
                        // В кадрах без нажатия ошибка не показывается повторно.
                        self.action_error = None;
                    }
                    if ui.small_button("📋 скопировать путь").clicked() {
                        ui.ctx().copy_text(path_text.clone());
                    }
                });
                // Ошибку открытия показываем ровно один кадр после нажатия.
                if let Some(err) = self.action_error.take() {
                    ui.colored_label(egui::Color32::from_rgb(200, 60, 60), format!("⚠ {err}"));
                }
            }
            None => {
                ui.label(
                    egui::RichText::new(
                        "Папка хранилища не настроена — задайте её в админ-панели (/admin)",
                    )
                    .small()
                    .weak(),
                );
            }
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("📁 Файловый сервер");
            ui.add_space(8.0);

            if let Some(err) = &self.error {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 60, 60),
                    format!("⚠ {err}"),
                );
                ui.add_space(8.0);
                if ui.button("Повторить запуск").clicked() {
                    self.error = None;
                    self.start_server();
                }
                return;
            }

            let Some(info) = &self.server else { return };
            let url = info.url.clone();

            // --- Локальный адрес ---
            ui.label("Сервер запущен. Адрес для других устройств в сети:");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(&url)
                        .monospace()
                        .size(19.0)
                        .color(egui::Color32::from_rgb(40, 100, 210)),
                );
                if ui.small_button("📋 копировать").clicked() {
                    ctx.copy_text(url.clone());
                }
            });
            ui.add_space(10.0);

            // Ленивая генерация текстуры QR (нужен контекст рендера).
            if self.qr_texture.is_none() {
                match Self::qr_rgba(&url) {
                    Some((rgba, dims)) => {
                        let img = egui::ColorImage::from_rgba_unmultiplied(dims, &rgba);
                        let texture =
                            ctx.load_texture("qrcode", img, egui::TextureOptions::NEAREST);
                        self.qr_texture = Some(texture);
                    }
                    None => {
                        self.error = Some(format!("Не удалось построить QR-код для {url}"));
                        return;
                    }
                }
            }

            // --- QR-код рядом с адресом ---
            let size = (ui.available_width() - 16.0)
                .min(ui.available_height() - 120.0)
                .clamp(140.0, 360.0);
            ui.centered_and_justified(|ui| {
                let resp = ui.add(
                    egui::Image::new(self.qr_texture.as_ref().unwrap())
                        .fit_to_exact_size(egui::vec2(size, size))
                        .sense(egui::Sense::click()),
                );
                if resp.clicked() {
                    open_in_browser(&url);
                }
            });
            ui.add_space(6.0);

            ui.separator();
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                if ui.button("🌐 Открыть в браузере").clicked() {
                    open_in_browser(&url);
                }
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Наведите камеру телефона на QR-код, чтобы открыть страницу загрузки",
                    )
                    .small()
                    .weak(),
                );
            });
            ui.add_space(6.0);

            // --- Папка хранилища (если настроена через конфиг/админку) ---
            // Читаем состояние каждый кадр: админ может сменить директорию
            // через веб-интерфейс, не перезапуская GUI.
            self.storage_section(ui);
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Закрываем окно — останавливаем HTTP-сервер.
        self.stop_server();
    }
}

/// Лучший кандидат на «тот самый» локальный адрес в LAN.
fn local_ip() -> Option<IpAddr> {
    local_ip_address::local_ip().ok()
}

/// Открыть ссылку в системном браузере (крейт `open` — tiny, без зависимостей GUI).
fn open_in_browser(url: &str) {
    if let Err(e) = open::that(url) {
        eprintln!("Не удалось открыть браузер: {e}");
    }
}

/// Открыть папку в проводнике ОС (Windows: explorer, macOS: Finder, Linux: xdg-open).
/// Возвращает `Some(описание)` при неудаче — чтобы показать ошибку прямо в окне.
fn open_path(path: &std::path::Path) -> Option<String> {
    match open::that(path) {
        Ok(()) => None,
        Err(e) => Some(format!("не удалось открыть {}: {e}", path.display())),
    }
}
