# Azura — WebGuard Inspector v0.8.0

*Local Source Security Workspace.* Logo: `assets/icon.png` (asli) dan `assets/azura-logo.png` (dibersihkan, persegi);
ikon aplikasi `src/WebGuard.Desktop/Assets/azura.ico` (16–256 px).

Aplikasi desktop Windows (WPF, .NET 10) untuk inspeksi keamanan source code secara lokal.
Setelah inventory + SHA-256, aplikasi menjalankan engine deteksi (Semgrep, Gitleaks, OSV-Scanner, YARA-X) dan lookup
threat intelligence (OSV.dev, CISA KEV, MalwareBazaar, ThreatFox), lalu menampilkan hasilnya di halaman Findings (Phase 2).
Phase 3 menambahkan AI Analyst dengan model lokal dan server **MCP** lokal untuk agen AI (Claude Code, LM Studio, Cursor, …).
v0.5 menambahkan **Phase 4 — Second Brain**: setiap scan (termasuk yang aman), temuan, analisis AI dan keputusan validasi
dicatat sebagai catatan Markdown yang saling terhubung di vault **Obsidian**.
v0.6 menambahkan **Fixing**: Claude (lewat Claude Code CLI dengan login Anda) mengusulkan perbaikan per temuan, Anda meninjau
diff-nya, lalu Apply dengan backup dan Undo. Temuan yang dinilai false positive hanya diusulkan sampai Anda konfirmasi.

> **Catatan:** engine adalah tool CLI eksternal yang harus di-install sendiri (lihat *Engine Phase 2*).
> Engine yang tidak ter-install dilaporkan sebagai *Not installed* dan scan tetap berjalan.
> AI Analyst butuh server model lokal (LM Studio/Ollama) — lihat *AI Analyst dan MCP*. Second Brain butuh vault Obsidian — lihat *Second Brain (Phase 4)*.

## Fitur

| Fitur | Status |
| --- | --- |
| Browse folder lokal (Ctrl+O), validasi path, folder terakhir diingat | Implemented |
| Inventory rekursif, exclusion folder dependency/build (bisa diubah di Settings) | Implemented |
| SHA-256 streaming, paralel (1–8 reader), batas ukuran hash bisa diatur | Implemented |
| Tidak mengikuti symlink/junction (scan tidak bisa keluar dari folder terpilih) | Implemented |
| Progress berbasis byte, elapsed time, cancel (Esc) | Implemented |
| Dashboard: alur 3 langkah, stat cards, delta jumlah file vs scan sebelumnya | Implemented |
| File Inventory: search (Ctrl+F) nama/hash, filter status, sort, copy hash/path | Implemented |
| File Details panel: path, ukuran, last modified, SHA-256 + copy, durasi hash | Implemented |
| Inventory hints (berdasarkan nama file saja, bukan finding): .env, key, config, lockfile, binary | Implemented |
| Ekspor laporan JSON schema 1.1 (Ctrl+E) | Implemented |
| Scan History (sesi aktif) | Implemented |
| Dark theme default + Light theme, title bar Windows 11 ikut tema | Implemented |
| Settings tersimpan di `%LOCALAPPDATA%\WebGuardInspector\settings.json` | Implemented |
| Engine Semgrep (SAST, rule lokal, `--metrics=off`), Gitleaks (secret, `--redact`), OSV-Scanner (dependency), YARA-X (signature) | Implemented (Phase 2) |
| `ExternalProcessRunner`: path absolut .exe saja, tanpa shell, timeout, batas output; cancel/timeout menghentikan semua proses turunan (Windows Job Object) | Implemented (Phase 2) |
| Rule bawaan `rules\semgrep` dan `rules\yara`; rule kustom lewat `EngineRulePaths` di settings.json | Implemented (Phase 2) |
| Finding di luar inventory (folder dikecualikan, path keluar root) dibuang; dedupe per fingerprint | Implemented (Phase 2) |
| Findings: evidence ter-redaksi, CWE/CVE/GHSA, remediasi, status per engine | Implemented (Phase 2) |
| OSV.dev package lookup, MalwareBazaar + ThreatFox hash lookup, cache lokal `intel-cache` | Implemented (Phase 2, opt-in) |
| CISA KEV: finding dependency yang CVE-nya dieksploitasi aktif ditandai **KEV** dan dinaikkan ke Critical | Implemented (Phase 2, opt-in) |
| AI Analyst lokal (OpenAI-compatible: LM Studio, Ollama, llama.cpp): ringkasan, alasan risiko, usulan perbaikan per finding | Implemented (Phase 3) |
| Konteks AI: cuplikan kode bernomor baris, secret diredaksi (`SourceRedactor`), hanya endpoint localhost | Implemented (Phase 3) |
| Server MCP stdio `WebGuard.Mcp.exe`: 7 tool, scope satu folder, tool berisiko hanya dengan `--allow`, audit log | Implemented (Phase 3) |
| Second Brain di vault Obsidian: Dashboard, Projects, Scans (termasuk scan aman), Findings, Rules | Implemented (Phase 4) |
| Validasi temuan (Confirmed, FalsePositive, AcceptedRisk, Fixed, …) di aplikasi atau properti `status` di Obsidian; dipakai lagi di scan berikutnya | Implemented (Phase 4) |
| Temuan yang hilang di scan berikutnya ditandai `present: false` ("likely fixed"); muncul lagi = regresi | Implemented (Phase 4) |
| Pencarian kata kunci + semantik (embedding lokal nomic-embed via LM Studio) | Implemented (Phase 4) |
| Tool MCP `search_similar_findings`, `save_security_finding` | Implemented (Phase 4) |
| Fixing: usulan perbaikan dari Claude Code CLI, diff, Apply dengan backup, Undo, saran false positive | Implemented (v0.6) |
| Model `SecurityFinding`, `FindingFingerprint`, `SecretRedactor`, `ValidationStatus` | Implemented |

## Instalasi (Setup.exe)

Unduh/jalankan `Azura-WebGuard-Inspector-Setup-<versi>.exe` (~70 MB). Installer:

- memasang aplikasi **self-contained** (runtime .NET 10 ikut; PC tujuan tidak perlu .NET) ke
  `%LOCALAPPDATA%\Programs\Azura WebGuard Inspector` tanpa hak administrator (dialog Setup juga menawarkan *all users*);
- menyertakan **Gitleaks, OSV-Scanner dan YARA-X** (`tools\`, lisensi di `tools\licenses`) sehingga langsung jalan offline;
- menawarkan centang untuk memasang secara online: **Semgrep** (Python 3 via winget bila belum ada, lalu `pip install --user
  semgrep`; tercentang default), **Claude Code CLI**, **Obsidian**, **LM Studio**. Prosesnya tampil di jendela konsol dan
  dicatat di `%LOCALAPPDATA%\WebGuardInspector\logs\install-deps.log`; bisa diulang lewat Start Menu →
  *Install or repair dependencies*;
- membuat shortcut Start Menu (dan Desktop bila dipilih) serta uninstaller di Apps & Features. Uninstall tidak menghapus
  settings, backup Fixing maupun vault.

### Wizard first-run (wajib)

Saat pertama dibuka, Azura hanya menampilkan wizard 8 langkah sampai selesai: Welcome → Security engines (status tiap
engine) → Privacy (lookup online atau offline saja, abuse.ch key) → Local AI → Claude fixing → Second Brain → Preferences
(tema, paralelisme, folder yang dikecualikan) → ringkasan. Setiap fitur opsional harus dijawab *Use it* / *Don't use*;
isian divalidasi (endpoint AI harus lokal, vault harus ada, path claude.exe harus .exe). Nilai tiap langkah disimpan saat
lanjut, dan wizard dianggap selesai hanya setelah **Finish** — menutup aplikasi di tengah jalan akan menampilkannya lagi.
Wizard bisa diulang dari **Settings → Run setup wizard**.

### Updates dan About (Settings)

- **Updates**: Azura mengecek rilis terbaru di GitHub (`api.github.com/repos/agnanzakariya/WebGuardInspector/releases/latest`)
  saat start, maksimal sekali sehari, bila diizinkan (ditanyakan di wizard, bisa diubah di Settings), atau lewat **Check now**.
  Hanya metadata rilis publik yang diminta; tidak ada data proyek yang dikirim. Bila ada versi baru, top bar menampilkan
  *Update x.y.z available* dan Settings menampilkan catatan rilis.
- **Download & install** mengunduh `Azura-WebGuard-Inspector-Setup-<versi>.exe` hanya dari
  `github.com/agnanzakariya/WebGuardInspector/releases/download/…`, mencocokkan SHA-256 dengan yang dipublikasikan di rilis
  (digest aset GitHub, file `<setup>.sha256`, atau baris `SHA-256: …` di catatan rilis), lalu menjalankannya setelah
  dikonfirmasi; Azura menutup diri agar file bisa diganti. Tanpa checksum, installer tidak dijalankan otomatis.
- **About**: identitas aplikasi (logo, versi, pembuat, link GitHub dan laporan masalah), komponen dan versinya (aplikasi,
  MCP server, runtime .NET, Windows, Claude Code, AI lokal, semua engine), lokasi data dengan tombol **Open** (instalasi,
  settings, log, backup Fixing, unduhan update, cache intelijen, vault) dan lisensi pihak ketiga.

### Merilis versi baru

1. Naikkan `<Version>` di `Directory.Build.props` dan `AppInfo.Version`.
2. `.\installer\build-installer.ps1` → `installer\out\Azura-WebGuard-Inspector-Setup-<versi>.exe` + `.sha256`.
3. Buat GitHub Release dengan tag `v<versi>` dan lampirkan kedua file. Pengguna mendapat pemberitahuan saat start berikutnya.

### Membangun installer

```powershell
winget install JRSoftware.InnoSetup      # sekali saja
.\installer\build-installer.ps1           # tests, publish self-contained, bundel engine, compile azura.iss
# hasil: installer\out\Azura-WebGuard-Inspector-Setup-<versi>.exe
```

Engine bawaan diambil dari PATH/WinGet di PC build (atau `-ToolsDir <folder>`).

## Persyaratan

- Windows 11, Visual Studio Community 2026 dengan workload **.NET desktop development**
- .NET 10 SDK (`global.json` menerima 10.0.100 ke atas)
- **Tidak ada paket NuGet pihak ketiga** — build berjalan offline.
- Opsional (Phase 2): satu atau lebih engine CLI, lihat di bawah.

## Build dan jalankan

Visual Studio 2026: buka `WebGuardInspector.slnx`, set **WebGuard.Desktop** sebagai startup project, tekan **F5**.

PowerShell:

```powershell
Set-Location C:\Dev\WebGuardInspector
.\build.ps1          # restore + build + 78 tests
.\build.ps1 -Run     # ... lalu jalankan aplikasi
```

Expected output:

```text
== Build (Debug) ==
Build succeeded.
== Tests ==
  PASS  CoreTests.Byte_formatting_is_human_readable (1 ms)
  ...
PASS: 78 tests
PASS: build and tests completed
```

Uji cepat: Browse ke `samples\demo-project`, tekan **Start Scan** (F5). Hasil yang diharapkan:
5 file (README, Program.cs, appsettings.json, .env.example, package-lock.json), folder `node_modules`
dikecualikan, dan panel AI Analyst menampilkan hint *Possible secret containers*, *Configuration files*,
dan *Dependency manifests*.

## Shortcut

| Tombol | Aksi |
| --- | --- |
| Ctrl+O | Browse folder |
| F5 | Start scan |
| Esc | Cancel scan |
| Ctrl+F | Fokus ke kotak search di halaman aktif |
| Ctrl+E | Ekspor JSON |

## Struktur solution

```text
src/
  WebGuard.Core          Domain model + semua kontrak (Scanning, Findings, Detection, Intelligence, AI, Knowledge, Reporting)
  WebGuard.Scanner       LocalFolderScanner, JsonReportExporter, InMemoryScanHistoryStore
  WebGuard.Detection     SemgrepEngine, GitleaksEngine, OsvScannerEngine, YaraXEngine + rule bawaan
  WebGuard.Intelligence  OSV.dev, CISA KEV, MalwareBazaar, ThreatFox, cache intelligence
  WebGuard.AI            LocalAiSecurityAnalyst, LocalEmbeddingService, OpenAiCompatibleClient, StdioMcpServerHost, ClaudeCodeFixer
  WebGuard.Mcp           Server MCP stdio (WebGuard.Mcp.exe): McpServer, McpToolset, McpAuditLog
  WebGuard.Persistence   ObsidianSecondBrain (vault Markdown), MarkdownNote
  WebGuard.Presentation  ViewModels (net10.0, tanpa WPF) — dapat diuji di mana saja
  WebGuard.Desktop       WPF views, tema, layanan dialog/clipboard, composition root (App.xaml.cs)
tests/
  WebGuard.Tests         Test runner tanpa dependency (78 tests)
```

Aturan dependency: library hanya bergantung ke `WebGuard.Core`; `WebGuard.Desktop` (`App.Compose`) dan `WebGuard.Mcp`
(`Program.cs`) adalah composition root yang merangkai implementasi. ViewModel tidak mereferensikan WPF, sehingga logika UI diuji
oleh `WebGuard.Tests`.

## Engine Phase 2

Install engine yang diinginkan; aplikasi mendeteksi .exe otomatis dari PATH, WinGet Links, Scoop shims,
`%USERPROFILE%\go\bin` dan `%USERPROFILE%\.cargo\bin`, atau isi path absolut di **Settings → Engine executables**.

| Engine | Install (contoh) | Catatan |
| --- | --- | --- |
| Semgrep CE | `pip install --user semgrep` | Rule bawaan di `rules\semgrep`; tidak memakai registry/login. Folder Scripts Python ikut dicari otomatis; file yang terkunci antivirus dilewati dan dilaporkan |
| Gitleaks | `winget install Gitleaks.Gitleaks` | `gitleaks dir` (≥ 8.19) atau `detect --no-git` untuk versi lama |
| OSV-Scanner | `winget install Google.OSVScanner` | Mengirim nama/versi package ke OSV.dev, jadi hanya aktif bila *external lookups* diizinkan |
| YARA-X | `winget install VirusTotal.YARA-X` | Rule bawaan di `rules\yara` (web shell, loader obfuscated, downloader, obfuscation PHP) |
| MalwareBazaar + ThreatFox | Auth-Key gratis dari auth.abuse.ch (satu key untuk keduanya) | Hanya SHA-256 file executable/arsip/script, maks. 200 per scan |
| CISA KEV | Tidak perlu install | Katalog publik diunduh (tanpa data proyek), cache 24 jam; menandai finding OSV-Scanner |

### Rule PHP (v0.6.1)

Untuk aplikasi PHP, plugin/tema WordPress dan paket pihak ketiga ("nulled"):

- `rules\semgrep\webguard-php.yaml` — 13 rule. Mode *taint* (dalam satu fungsi) dari input request (`$_GET`, `$_POST`,
  `$_REQUEST`, `$_COOKIE`, `$_FILES`, header, `php://input`) ke: SQL injection (mysqli, PDO, `$wpdb`), command injection,
  code injection (`eval`, `assert`, callback dinamis), file inclusion, path traversal, `unserialize`, XSS. Ditambah pola:
  `extract`/`parse_str`, `preg_replace` /e, kode yang diunduh lalu dieksekusi, kredensial hardcoded, hash password MD5/SHA-1,
  verifikasi TLS dimatikan. Sanitizer umum (`intval`, `htmlspecialchars`, `esc_*`, `$wpdb->prepare`, `escapeshellarg`,
  `basename`) dikenali.
- `rules\yara\webguard-php.yar` — 7 rule obfuscation/backdoor: nama fungsi berbahaya dalam escape hex/oktal atau `strrev`,
  parameter request dipanggil sebagai fungsi, eval/include dari URL, rantai `chr()`, tabel `$GLOBALS` ter-obfuscate,
  pembuatan akun administrator WordPress. Semua butuh tag `<?php`, jadi dokumentasi/rule tidak ikut cocok.
- Diuji dengan Semgrep 1.183 dan YARA-X 1.22: setiap baris rentan di sampel terdeteksi, varian aman tidak.

Setiap engine berjalan berurutan setelah hashing dengan timeout 10 menit. Engine yang gagal dicatat di ringkasan
(halaman Findings dan laporan JSON) tanpa membatalkan scan.

## AI Analyst dan MCP (Phase 3)

**AI Analyst** — menjelaskan satu finding: ringkasan, kenapa berisiko (atau kenapa mungkin false positive), dan usulan
perbaikan. Hasil selalu ditandai *AI hypothesis — not verified*; tidak ada file yang diubah.

1. Install [LM Studio](https://lmstudio.ai), unduh model chat, muat, lalu nyalakan server lokal. Lewat CLI:
   `lms get qwen/qwen3.5-9b`, `lms load qwen/qwen3.5-9b -c 8192`, `lms server start --port 1234`
   (atau **Developer → Start Server**). Ollama juga bisa: `http://127.0.0.1:11434/v1`.
2. Settings → *AI Analyst (local)*: endpoint dan model (kosong = model chat pertama yang dimuat).
3. Findings → pilih finding → **Analyze with AI**.

Untuk model *reasoning* (Qwen3.5/3.6, gpt-oss) WebGuard mengirim `reasoning_effort: "none"`; tanpa itu model di CPU
menghabiskan seluruh jatah token untuk "berpikir" dan tidak memberi jawaban. Diuji live dengan Qwen3.5 9B (Q4_K_M) di CPU
i7-1185G7 tanpa GPU: ±30–60 detik per finding.

Hanya endpoint localhost yang diterima. Model menerima cuplikan kode di sekitar finding yang **sudah diredaksi**
(token, password, private key, connection string) dan diberi instruksi bahwa kode adalah data tak tepercaya
(pertahanan terhadap prompt injection di dalam kode yang dipindai). File biner tidak pernah dikirim.

**Server MCP** — `WebGuard.Mcp.exe` (ikut di folder aplikasi) dijalankan oleh klien MCP lewat stdio:

```text
WebGuard.Mcp.exe --root <folder proyek> [--allow run_security_rules,lookup_vulnerability,lookup_malware_hash] [--audit-log <file>]
```

Halaman **AI Analyst** membuat konfigurasi `mcpServers` dan perintah `claude mcp add` untuk folder aktif.

| Tool | Akses | Default |
| --- | --- | --- |
| `list_project_files`, `read_source_context`, `get_dependency_manifest`, `propose_remediation` | Read-only (konten diredaksi) | Aktif |
| `run_security_rules` | Menjalankan engine yang di-allow-list | Hanya dengan `--allow` |
| `lookup_vulnerability`, `lookup_malware_hash` | Lookup jaringan (juga butuh izin di Settings) | Hanya dengan `--allow` |
| `search_similar_findings` | Read-only: cari di Second Brain | Aktif (butuh vault) |
| `save_security_finding` | Menulis temuan sebagai hipotesis (`NeedsReview`) | Hanya dengan `--allow` |

Semua path dibatasi ke `--root` (`..`, path absolut lain, dan symlink/junction ditolak). Setiap panggilan — termasuk
yang ditolak — dicatat di `%LOCALAPPDATA%\WebGuardInspector\mcp-audit.jsonl`.

## Second Brain (Phase 4)

Atur folder vault di **Settings → Second Brain (Obsidian)** (mis. `D:\2nd Brain\WebGuard`) lalu buka folder itu di Obsidian
(*Open folder as vault*). Dengan pencatatan otomatis aktif, setiap scan dan analisis AI langsung dicatat:

```text
Dashboard.md                       ringkasan: proyek, temuan Critical/High yang masih terbuka, scan terbaru
Projects/<proyek>.md               riwayat scan proyek + temuan saat ini
Scans/<tanggal jam> <proyek>.md    satu scan: engine, hasil (clean / findings / not-analyzed), inventaris
Findings/<judul> (<id>).md         satu temuan unik (fingerprint): bukti teredaksi, kemunculan, analisis AI, riwayat validasi
Rules/<engine> — <rule>.md         semua temuan sebuah aturan + catatan tim tentang cara memperbaikinya
```

- Catatan memakai *properties* (severity, status, CWE, present, first/last seen, tags) dan wiki link, jadi bisa dipakai
  di Search, Graph view, Bases/Dataview Obsidian.
- WebGuard hanya menulis properti miliknya dan blok `<!-- webguard:... -->`; teks Anda (bagian **My notes** dan di luar
  blok) serta properti tambahan Anda tidak pernah ditimpa. Properti `status` hanya diubah oleh keputusan validasi.
- Scan tanpa engine yang berjalan dicatat sebagai `not-analyzed`, bukan "aman".
- Secret selalu diredaksi sebelum ditulis; embedding untuk pencarian disimpan di `.webguard/` (diabaikan Obsidian).

## Fixing dengan Claude (v0.6)

Butuh Claude Code CLI yang sudah login dengan akun Claude Anda:

```powershell
irm https://claude.ai/install.ps1 | iex          # memasang %USERPROFILE%\.local\bin\claude.exe
& "$env:USERPROFILE\.local\bin\claude.exe"      # sekali saja: pilih login akun Claude (/login)
```

Lalu buka halaman **Fixing** (di bawah Findings) setelah scan: **Fix with Claude** untuk satu temuan atau
**Fix all open findings** untuk semua yang belum dijawab. Path `claude.exe` dan model (mis. `sonnet`, `opus`) bisa diatur di
**Settings → Fixing with Claude**.

- Yang dikirim ke Anthropic hanya file tempat temuan berada, sudah diredaksi. Claude dijalankan dengan `--tools ""`,
  `--strict-mcp-config`, `--setting-sources ""`, dari folder sementara yang kosong: ia tidak bisa membaca proyek, menjalankan
  perintah, atau mengubah file. Jawabannya JSON (dicek dengan `--json-schema`) berisi edit teks yang persis.
- Edit diterapkan semua atau tidak sama sekali; setiap `old_text` harus cocok tepat satu kali. `[REDACTED]` dicocokkan
  sebagai wildcard dan nilai aslinya dikembalikan, jadi teks `[REDACTED]` tidak pernah tertulis ke kode.
- **Apply** menyalin file asli byte-per-byte ke `%LOCALAPPDATA%\WebGuardInspector\fix-backups` (untuk Undo), menjaga BOM dan
  CRLF, lalu mencatat status `Fixed` di Second Brain. **Undo** mengembalikan file asli (ditolak bila file sudah berubah lagi).
- Versi lama yang rentan juga disimpan di **`<proyek>\wreck\`** (sub-folder asli dipertahankan) sebagai
  `nama.ext.yyyyMMdd-HHmmss.wreck`: setiap baris dikomentari sesuai bahasanya (`//`, `#`, `<!-- -->`, …; tag PHP `<?`/`?>`
  dipatahkan), dengan header berisi file asal, waktu, alasan dan lokasi backup. Ekstensi `.wreck` membuatnya tidak dieksekusi
  server, dan folder `wreck` selalu dikecualikan dari scan. Jangan ikut men-deploy folder ini. Undo menghapus salinan wreck-nya.
- Verdict `false_positive` hanya saran; **Confirm false positive** mencatat `FalsePositive`. File biner, non-UTF-8 atau
  lebih dari 1 MB tidak dikirim dan ditandai *Needs manual action*.

## Prinsip keamanan

- Read-only: aplikasi tidak pernah mengeksekusi, memodifikasi, atau mengunggah file yang dipindai.
- Berjalan sebagai user biasa (`asInvoker`), tanpa elevasi.
- Lookup threat intelligence bersifat opt-in dan hanya boleh mengirim koordinat package atau SHA-256.
- Output AI selalu ditandai sebagai hipotesis sampai divalidasi manusia; AI hanya memakai model lokal.
- Server MCP read-only secara default, dibatasi ke satu folder, dan diaudit.

## Changelog

**0.8.0** — Updates dan About
- `GitHubUpdateService`: cek GitHub Releases (harian saat start bila diizinkan, atau manual), unduh installer hanya dari rilis repo
  ini, verifikasi SHA-256, jalankan setelah konfirmasi. Pemberitahuan update di top bar; opsi update di wizard (langkah Privacy).
- Settings → Updates dan About: identitas, komponen dan versi, lokasi data dengan tombol Open, lisensi pihak ketiga.
- `build-installer.ps1` menulis `<setup>.sha256`. 78 tests.

**0.7.0** — Installer dan wizard first-run
- `installer\build-installer.ps1` + `azura.iss` (Inno Setup 6): Setup.exe self-contained win-x64, engine Gitleaks/OSV-Scanner/YARA-X
  dibundel beserta lisensinya, dependencies opsional (Semgrep, Claude Code, Obsidian, LM Studio) lewat `install-deps.ps1`.
- Wizard first-run wajib 8 langkah (`SetupWizardViewModel`), bisa diulang dari Settings; shortcut aplikasi diblokir selama wizard tampil.
- Diuji: install silent per-user, aplikasi terpasang berjalan (5/5 engine siap), uninstall bersih. 73 tests.

**0.6.1** — Rule PHP, nama dan ikon Azura
- Aplikasi bernama **Azura** (sub: WebGuard Inspector) dengan logo ksatria; ikon dipakai untuk exe, jendela, taskbar dan `WebGuard.Mcp.exe`.
- 13 rule Semgrep PHP (taint dari input request: SQLi, command/code injection, file inclusion, path traversal, unserialize, XSS;
  serta kredensial hardcoded, hash password lemah, TLS off, `preg_replace` /e, remote code load, `extract`).
- 7 rule YARA-X untuk obfuscation/backdoor PHP dan admin WordPress tersembunyi.
- Evidence Semgrep kini diredaksi; redactor juga menangkap `define('KEY', '…')` dan `'password' => '…'`. 70 tests.
- Fixing: versi lama file yang diperbaiki disimpan sebagai salinan berkomentar `*.wreck` di folder `wreck` proyek (tidak di-scan).
- Catatan Second Brain ditulis langsung (tanpa file sementara + rename): Obsidian melewatkan event rename saat scan menulis
  banyak catatan sekaligus, sehingga sebagian catatan "not found" sampai Obsidian di-reload.

**0.6.0** — Fixing dengan Claude
- Halaman Fixing: usulan perbaikan per temuan lewat Claude Code CLI (tanpa tool, tanpa akses proyek), diff, Apply dengan backup, Undo.
- `FixPatcher` (edit persis, sadar redaksi, all-or-nothing) dan `FixApplier` (backup di luar proyek, BOM/CRLF dijaga).
- Saran false positive dengan konfirmasi; usulan disimpan sebagai analisis AI di Second Brain (diff diredaksi).
- `ExternalProcessRunner` dapat mengirim stdin. 67 tests; diuji live dengan Claude Code 2.1.317.

**0.5.0** — Phase 4 (Second Brain)
- `ObsidianSecondBrain`: catatan Markdown di vault Obsidian untuk setiap scan (termasuk yang aman), temuan, proyek, aturan, dashboard.
- Validasi dua arah (aplikasi ↔ properti `status` Obsidian) dan diterapkan ke scan berikutnya; temuan yang hilang ditandai `present: false`.
- Analisis AI tersimpan sebagai hipotesis; tombol *Open in Obsidian*; halaman Second Brain dengan pencarian kata kunci + semantik.
- Tool MCP `search_similar_findings` dan `save_security_finding`. 59 tests; diuji live di vault pengguna.

**0.4.0** — Phase 3
- `LocalAiSecurityAnalyst` + `OpenAiCompatibleClient` (LM Studio/Ollama/llama.cpp, hanya localhost), tombol *Analyze with AI* di Findings.
- `FindingContextBuilder`, `SourceRedactor`, `ProjectScope` di Core: konteks bernomor baris, redaksi secret, scope folder.
- Server MCP stdio `WebGuard.Mcp` (JSON-RPC 2.0, MCP 2025-06-18): 7 tool, approval via `--allow`, anotasi tool, audit log.
- Halaman AI Analyst: status runtime, katalog tool, konfigurasi klien MCP + perintah Claude Code.
- Status engine, AI dan intelligence dicek bersamaan saat aplikasi dibuka. 53 tests.
- Diuji live dengan LM Studio + Qwen3.5 9B: analisis RCE `eval` dan secret Stripe benar, secret tidak terkirim ke model.

**0.3.0** — Phase 2
- Adapter Semgrep, Gitleaks, OSV-Scanner, YARA-X di atas `ExternalToolEngine` + `ExternalProcessRunner`.
- `LocalFolderScanner` menjalankan engine (fase *Analyzing*), memfilter finding di luar inventory, dedupe per fingerprint.
- Intelligence: OSV.dev, MalwareBazaar + ThreatFox, `FileIntelligenceCache`; semua opt-in.
- `IFindingEnricher` + `KnownExploitedEnricher`: CVE di katalog CISA KEV ditandai KEV dan dinaikkan ke Critical setelah engine selesai.
- UI: path engine dan Auth-Key di Settings, lookup package di Intelligence, detail finding (evidence, referensi, remediasi).
- 42 tests (parser, orkestrasi, process runner, privasi intelligence, enricher KEV, ThreatFox).
- Diuji dengan tool asli: Semgrep 1.183, Gitleaks 8.30, OSV-Scanner 2.7, YARA-X 1.22 (rule ID Semgrep tanpa path instalasi, retry saat file terkunci, redaksi parsial Gitleaks); KEV diuji live: Log4Shell CVE-2021-44228 ditandai.

**0.2.0**
- Desain baru: sidebar 8 halaman, alur Select Folder → Scan → Investigate, stat cards, inventory + detail panel, dark/light theme.
- Scanner: hashing paralel, progress berbasis byte, `ScanOptions` yang bisa dikonfigurasi, `LastModified`, durasi hash, jumlah folder dikecualikan.
- Report JSON schema 1.1 (camelCase, enum sebagai string, ringkasan engine, daftar findings).
- Kontrak Phase 2–4 dan stub *Planned*.
- ViewModel dipindah ke `WebGuard.Presentation`; 23 tests (v0.1: 1 smoke test).

**0.1.0** — Inventory folder lokal, SHA-256, dashboard WPF, cancel, ekspor JSON.
