//! Нативное GUI-окно сервера (крейт `eframe`/`egui` — лёгкий immediate-mode UI,
//! без Electron/WebView, в отличие от тяжёлого `tauri`).
//!
//! Окно показывает локальный IP-адрес машины и QR-код на адрес сервера
//! (`http://<ip>:<порт>`): камеру телефона наводят на QR — и открывают страницу
//! загрузки файлов. Рядом — кнопка «Открыть в браузере».
//!
//! Сервер поднимается внутри окна на фоновой tokio-задаче; как только сокет
//! привязан, порт узнаётся через `listener.local_addr()` — поэтому можно
//! стартовать с портом 0 («любой свободный»).

use std::net::{IpAddr, TcpListener as StdTcpListener};

use eframe::egui;

/// Размер QR-картинки в пикселях (рендерим с запасом, на экране масштабируется).
const QR_PIXELS: u32 = 512;

/// Запускает окно приложения; функция не возвращает управление до закрытия окна.
pub fn run(bind_host: String, bind_port: u16) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 520.0])
            .with_min_inner_size([360.0, 420.0])
            .with_title("Файловый сервер"),
        ..Default::default()
    };
    eframe::run_native(
        "file-server-gui",
        options,
        Box::new(move |cc| Ok(Box::new(GuiApp::new(cc, bind_host, bind_port)))),
    )
}

struct ServerInfo {
    /// URL для QR и кнопки «открыть» — виден из GUI-потока.
    url: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

struct GuiApp {
    bind_host: String,
    bind_port: u16,
    /// Пакет: сервер + shutdown-канал. Забирается при закрытии окна,
    /// чтобы корректно остановить axum.
    server: Option<ServerInfo>,
    qr_texture: Option<egui::TextureHandle>,
    error: Option<String>,
}

impl GuiApp {
    fn new(_cc: &eframe::CreationContext<'_>, bind_host: String, bind_port: u16) -> Self {
        let mut app = Self {
            bind_host,
            bind_port,
            server: None,
            qr_texture: None,
            error: None,
        };
        app.start_server();
        app
    }

    /// Поднимает axum-сервер на отдельном tokio-runtime в фоновом потоке.
    fn start_server(&mut self) {
        // Предварительно проверяем, что сокет вообще можно привязать: если нет,
        // сразу показываем ошибку в окне вместо тихого молчания фонового потока.
        let probe_addr = format!("{}:{}", self.bind_host, self.bind_port);
        if let Err(e) = StdTcpListener::bind(&probe_addr) {
            self.error = Some(format!("Не удалось занять адрес {probe_addr}: {e}"));
            return;
        }

        let host = self.bind_host.clone();
        let port = self.bind_port;
        let (tx_url, rx_url) = std::sync::mpsc::channel::<Result<(String, tokio::sync::oneshot::Sender<()>), String>>();
        let (tx_shutdown, rx_shutdown) = tokio::sync::oneshot::channel::<()>();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx_url.send(Err(format!("не удалось запустить tokio: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::bind((host.as_str(), port)).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = tx_url.send(Err(format!("не удалось привязаться к {host}:{port}: {e}")));
                        return;
                    }
                };
                let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                let ip = local_ip().unwrap_or(IpAddr::from([127, 0, 0, 1]));
                let url = format!("http://{ip}:{bound}");
                let app = crate::server_router();
                // Ждём shutdown-сигнал от окна либо аварию самого сервера.
                let serve = axum::serve(listener, app.with_state(crate::AppState::startup_state()));
                let _ = tx_url.send(Ok((url, tx_shutdown)));
                if let Err(e) = tokio::select! {
                    r = serve => r.map_err(|e| e.to_string()),
                    _ = rx_shutdown => Ok(()),
                } {
                    eprintln!("Ошибка сервера: {e}");
                }
            });
        });

        match rx_url.recv() {
            Ok(Ok((url, shutdown))) => {
                self.server = Some(ServerInfo { url, shutdown });
                // Просим перерисовать окно — появляется картинка QR.
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
        use qrcode::types::QrError;

        let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
        let image = code
            .render::<image::Luma<u8>>()
            .white_border(true)
            .min_dimensions(QR_PIXELS, QR_PIXELS)
            .build();
        let (w, h) = image.dimensions();
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for &p in image.as_raw() {
            let v = if p == 0 { 0 } else { 255 }; // Luma: 0 = чёрная модуль QR
            rgba.extend_from_slice(&[v, v, v, 255]);
        }
        let _ = QrError::Undetermined; // тип не нужен, но импорт фиксирует совместимость API
        Some((rgba, [w as usize, h as usize]))
    }

    fn show_error(&mut self, msg: String) {
        self.error = Some(msg);
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("📁 Файловый сервер");
            ui.add_space(8.0);

            if let Some(err) = &self.error {
                ui.colored_label(egui::Color32::from_rgb(200, 60, 60), format!("⚠ {err}"));
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
                    ui.output_mut(|o| o.copied_text = url.clone());
                }
            });
            ui.add_space(10.0);

            // --- QR-код рядом с адресом ---
            let tex = &self.qr_texture;
            let available = tex.is_some();
            let size = (ui.available_width() - 16.0).min(ui.available_height() - 60.0).max(140.0);

            ui.centered_and_justified(|ui| {
                if available {
                    let resp = ui.add(
                        egui::Image::new(tex.as_ref().unwrap())
                            .fit_to_exact_size(egui::vec2(size, size))
                            .sense(egui::Sense::click()),
                    );
                    if resp.clicked() {
                        open_in_browser(&url);
                    }
                } else {
                    ui.spinner();
                }
            });
            ui.add_space(6.0);

            // Ленивая генерация текстуры QR (нужен контекст рендера).
            if !available {
                let url_for_qr = url.clone();
                match Self::qr_rgba(&url_for_qr) {
                    Some((rgba, dims)) => {
                        let img = egui::ColorImage::from_rgba_unmultiplied(dims, &rgba);
                        let texture = ctx.load_texture("qrcode", img, egui::TextureOptions::NEAREST);
                        self.qr_texture = Some(texture);
                        ui.ctx().request_repaint();
                    }
                    None => self.show_error(format!(
                        "Не удалось построить QR-код для {url_for_qr}"
                    )),
                }
            }

            ui.separator();
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                if ui
                    .add_size(egui::Vec2::new(size.min(260.0), 34.0))
                    .button("🌐 Открыть в браузере")
                    .clicked()
                {
                    open_in_browser(&url);
                }
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new("Наведите камеру телефона на QR-код, чтобы открыть страницу загрузки")
                        .small()
                        .weak(),
                );
            });
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
