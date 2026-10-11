//! Simple HTML templates (no external template engine needed).

const PAGE_STYLE: &str = r#"
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;background:#f1f5f9;color:#1e293b;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:40px 16px}
.container{width:100%;max-width:720px}
h1{font-size:28px;margin-bottom:8px}
p.sub{color:#64748b;margin-bottom:24px}
.card{background:#fff;border-radius:14px;box-shadow:0 4px 16px rgba(15,23,42,.08);padding:28px;margin-bottom:20px}
.dropzone{border:2px dashed #94a3b8;border-radius:12px;padding:40px 20px;text-align:center;color:#64748b;cursor:pointer;transition:.2s}
.dropzone:hover,.dropzone.drag{border-color:#3b82f6;background:#eff6ff;color:#2563eb}
input[type=file]{display:none}
button{background:#3b82f6;color:#fff;border:none;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
button:hover{background:#2563eb}
button.secondary{background:#64748b}
button.danger{background:#ef4444}
button.danger:hover{background:#dc2626}
ul.files{list-style:none}
ul.files li{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid #e2e8f0}
ul.files li:last-child{border-bottom:none}
.fname{word-break:break-all;font-weight:500}
.fsize{color:#94a3b8;font-size:13px;white-space:nowrap}
.actions{display:flex;gap:8px}
a.dl{color:#3b82f6;text-decoration:none;font-weight:500;padding:6px 10px;border:1px solid #3b82f6;border-radius:8px}
a.dl:hover{background:#3b82f6;color:#fff}
.badge{display:inline-block;background:#fef3c7;color:#92400e;border-radius:8px;padding:6px 12px;font-size:14px;margin-bottom:16px}
.banner{background:#fee2e2;color:#991b1b;border-radius:8px;padding:12px 16px;margin-bottom:16px}
.ok{background:#dcfce7;color:#166534;border-radius:8px;padding:12px 16px;margin-bottom:16px}
input.dir{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px;margin-bottom:12px}
nav.top{width:100%;max-width:720px;display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
nav.top a{color:#3b82f6;text-decoration:none;font-weight:600}
.empty{color:#94a3b8;text-align:center;padding:20px}
progress{width:100%;margin-top:14px;height:8px}
.icon{font-size:40px;margin-bottom:12px}
"#;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// Page shown when the server has no storage directory configured yet.
pub fn page_not_configured() -> String {
    format!(
        r#"<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Файловый сервер — не настроен</title><style>{PAGE_STYLE}</style></head>
<body>
<nav class="top"><span style="font-weight:700;font-size:18px">&#128230; Файловый сервер</span>
<a href="/admin">Админ-панель &rarr;</a></nav>
<div class="container">
<div class="card" style="text-align:center">
<div class="icon">&#9888;&#65039;</div>
<h1>Сервер ещё не настроен</h1>
<p class="sub">Обмен файлами пока работать не будет.</p>
<p>Администратор должен открыть <a href="/admin" style="color:#3b82f6">админскую страницу</a>
и указать директорию, в которой сервер будет хранить файлы.
После этого загрузка и скачивание файлов станут доступны на этой странице.</p>
</div></div></body></html>"#
    )
}

/// Main page: upload + list of stored files.
pub fn page_main(dir: &str, files: &[(String, u64)], flash: Option<&str>) -> String {
    let list = if files.is_empty() {
        r#"<div class="empty">Пока нет ни одного файла — загрузите первый!</div>"#.to_string()
    } else {
        let items: String = files
            .iter()
            .map(|(name, size)| {
                let esc = html_escape(name);
                let url = url_encode(name);
                format!(
                    r#"<li><div><div class="fname">{esc}</div><div class="fsize">{}</div></div>
<div class="actions"><a class="dl" href="/download/{url}">Скачать</a>
<button class="danger" onclick="delFile('{url}')">Удалить</button></div></li>"#,
                    human_size(*size)
                )
            })
            .collect();
        format!("<ul class=\"files\">{items}</ul>")
    };

    let flash_html = match flash {
        Some(msg) => format!("<div class=\"ok\">{}</div>", html_escape(msg)),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Файловый сервер</title><style>{PAGE_STYLE}</style></head>
<body>
<nav class="top"><span style="font-weight:700;font-size:18px">&#128230; Файловый сервер</span>
<a href="/admin">Админ-панель &rarr;</a></nav>
<div class="container">
{flash_html}
<div class="card">
<h1>Загрузить файл</h1>
<p class="sub">Хранилище: <code>{}</code></p>
<div class="dropzone" id="dz">Перетащите файлы сюда или нажмите, чтобы выбрать
<input type="file" id="fin" multiple></div>
<progress id="prog" max="100" value="0" style="display:none"></progress>
</div>
<div class="card">
<h1>Доступные файлы</h1>
<p class="sub">Нажмите «Скачать», чтобы получить файл.</p>
{list}
</div>
</div>
<script>
const dz=document.getElementById('dz'),fin=document.getElementById('fin'),prog=document.getElementById('prog');
dz.onclick=()=>fin.click();
['dragover','dragenter'].forEach(e=>dz.addEventListener(ev=>{{}},false));
dz.addEventListener('dragover',e=>{{e.preventDefault();dz.classList.add('drag')}});
dz.addEventListener('dragleave',()=>dz.classList.remove('drag'));
dz.addEventListener('drop',e=>{{e.preventDefault();dz.classList.remove('drag');upload(e.dataTransfer.files)}});
fin.addEventListener('change',()=>upload(fin.files));
async function upload(files){{
 if(!files.length)return;
 const fd=new FormData();for(const f of files)fd.append('files',f);
 prog.style.display='block';prog.value=0;
 const xhr=new XMLHttpRequest();xhr.open('POST','/upload');
 xhr.upload.onprogress=e=>{{if(e.lengthComputable)prog.value=e.loaded/e.total*100}};
 xhr.onload=()=>location.reload();
 xhr.onerror=()=>alert('Ошибка загрузки');
 xhr.send(fd);
}}
function delFile(url){{fetch('/delete/'+url,{{method:'POST'}}).then(()=>location.reload())}}
</script>
</body></html>"#,
        html_escape(dir),
    )
}

/// Admin page: configure the storage directory.
pub fn page_admin(current: Option<&str>, message: Option<&str>, error: Option<&str>) -> String {
    let msg = match (error, message) {
        (Some(e), _) => format!("<div class=\"banner\">{}</div>", html_escape(e)),
        (None, Some(m)) => format!("<div class=\"ok\">{}</div>", html_escape(m)),
        (None, None) => String::new(),
    };
    let value = current.map(html_escape).unwrap_or_default();
    let status = match current {
        Some(_) => "<div class=\"ok\">Сервер настроен: обмен файлами работает.</div>",
        None => "<div class=\"banner\">Сервер не настроен: пользователи видят заглушку.</div>",
    };

    format!(
        r#"<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Админ-панель — Файловый сервер</title><style>{PAGE_STYLE}</style></head>
<body>
<nav class="top"><span style="font-weight:700;font-size:18px">&#128230; Админ-панель</span>
<a href="/">Открыть главную &rarr;</a></nav>
<div class="container">
{msg}{status}
<div class="card">
<h1>Директория для хранения файлов</h1>
<p class="sub">Укажите путь к папке на сервере, куда будут сохраняться загруженные файлы.
Папка будет создана автоматически, если её нет.</p>
<form method="post" action="/admin">
<input class="dir" type="text" name="directory" placeholder="/var/data/files" value="{value}">
<button type="submit">Сохранить</button>
<button class="secondary" type="submit" name="clear" value="1">Сбросить настройку</button>
</form>
</div>
</div></body></html>"#
    )
}

/// Minimal percent-encoding for file names in URLs (keeps unreserved chars).
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
