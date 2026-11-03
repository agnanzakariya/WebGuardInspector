# WebGuard Inspector v0.3.0 — Local Source Security Workspace

Aplikasi desktop Windows (WPF, .NET 10) untuk inspeksi keamanan source code secara lokal.
v0.3 menyelesaikan **Phase 2**: setelah inventory + SHA-256, aplikasi menjalankan engine deteksi
(Semgrep, Gitleaks, OSV-Scanner, YARA-X) dan lookup threat intelligence (OSV.dev, CISA KEV, MalwareBazaar, ThreatFox),
lalu menampilkan hasilnya di halaman Findings.

> **Catatan:** engine adalah tool CLI eksternal yang harus di-install sendiri (lihat *Engine Phase 2*).
> Engine yang tidak ter-install dilaporkan sebagai *Not installed* dan scan tetap berjalan.
> AI/MCP (Phase 3) dan Second Brain (Phase 4) masih berupa interface.

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
| `ExternalProcessRunner`: path absolut .exe saja, tanpa shell, timeout, batas output, kill process tree | Implemented (Phase 2) |
| Rule bawaan `rules\semgrep` dan `rules\yara`; rule kustom lewat `EngineRulePaths` di settings.json | Implemented (Phase 2) |
| Finding di luar inventory (folder dikecualikan, path keluar root) dibuang; dedupe per fingerprint | Implemented (Phase 2) |
| Findings: evidence ter-redaksi, CWE/CVE/GHSA, remediasi, status per engine | Implemented (Phase 2) |
| OSV.dev package lookup, MalwareBazaar + ThreatFox hash lookup, cache lokal `intel-cache` | Implemented (Phase 2, opt-in) |
| CISA KEV: finding dependency yang CVE-nya dieksploitasi aktif ditandai **KEV** dan dinaikkan ke Critical | Implemented (Phase 2, opt-in) |
| `IAiSecurityAnalyst`, `IMcpServerHost`, `McpToolCatalog` (9 tools) | Interface (Phase 3) |
| `ISecondBrainRepository`, `ITextEmbeddingService` | Interface (Phase 4) |
| Model `SecurityFinding`, `FindingFingerprint`, `SecretRedactor`, `ValidationStatus` | Implemented |

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
.\build.ps1          # restore + build + 42 tests
.\build.ps1 -Run     # ... lalu jalankan aplikasi
```

Expected output:

```text
== Build (Debug) ==
Build succeeded.
== Tests ==
  PASS  CoreTests.Byte_formatting_is_human_readable (1 ms)
  ...
PASS: 42 tests
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
  WebGuard.Detection     PlannedSecurityEngine + SemgrepEngine, GitleaksEngine, OsvScannerEngine, YaraXEngine (stub)
  WebGuard.Intelligence  PlannedVulnerabilityIntelligence, PlannedMalwareHashIntelligence (stub)
  WebGuard.AI            PlannedAiSecurityAnalyst, PlannedMcpServerHost (stub)
  WebGuard.Persistence   PlannedSecondBrainRepository (stub)
  WebGuard.Presentation  ViewModels (net10.0, tanpa WPF) — dapat diuji di mana saja
  WebGuard.Desktop       WPF views, tema, layanan dialog/clipboard, composition root (App.xaml.cs)
tests/
  WebGuard.Tests         Test runner tanpa dependency (23 tests)
```

Aturan dependency: semua project hanya bergantung ke `WebGuard.Core`; `WebGuard.Desktop` adalah satu-satunya
tempat implementasi dirangkai (`App.Compose`). ViewModel tidak mereferensikan WPF, sehingga logika UI diuji
oleh `WebGuard.Tests`.

## Engine Phase 2

Install engine yang diinginkan; aplikasi mendeteksi .exe otomatis dari PATH, WinGet Links, Scoop shims,
`%USERPROFILE%\go\bin` dan `%USERPROFILE%\.cargo\bin`, atau isi path absolut di **Settings → Engine executables**.

| Engine | Install (contoh) | Catatan |
| --- | --- | --- |
| Semgrep CE | `pip install --user semgrep` | Rule bawaan di `rules\semgrep`; tidak memakai registry/login. Folder Scripts Python ikut dicari otomatis; file yang terkunci antivirus dilewati dan dilaporkan |
| Gitleaks | `winget install Gitleaks.Gitleaks` | `gitleaks dir` (≥ 8.19) atau `detect --no-git` untuk versi lama |
| OSV-Scanner | `winget install Google.OSVScanner` | Mengirim nama/versi package ke OSV.dev, jadi hanya aktif bila *external lookups* diizinkan |
| YARA-X | `winget install VirusTotal.YARA-X` | Rule bawaan di `rules\yara` (web shell, loader obfuscated, downloader) |
| MalwareBazaar + ThreatFox | Auth-Key gratis dari auth.abuse.ch (satu key untuk keduanya) | Hanya SHA-256 file executable/arsip/script, maks. 200 per scan |
| CISA KEV | Tidak perlu install | Katalog publik diunduh (tanpa data proyek), cache 24 jam; menandai finding OSV-Scanner |

Setiap engine berjalan berurutan setelah hashing dengan timeout 10 menit. Engine yang gagal dicatat di ringkasan
(halaman Findings dan laporan JSON) tanpa membatalkan scan.

## Prinsip keamanan

- Read-only: aplikasi tidak pernah mengeksekusi, memodifikasi, atau mengunggah file yang dipindai.
- Berjalan sebagai user biasa (`asInvoker`), tanpa elevasi.
- Lookup threat intelligence bersifat opt-in dan hanya boleh mengirim koordinat package atau SHA-256.
- Output AI selalu ditandai sebagai hipotesis sampai divalidasi manusia.

## Changelog

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
