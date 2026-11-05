# Paper JOSS — draf dan daftar persiapan

`paper.md` + `paper.bib` adalah draf paper untuk [Journal of Open Source Software](https://joss.theoj.org) (bahasa Inggris,
format JOSS). Pratinjau PDF: tambahkan GitHub Action resmi `openjournals/openjournals-draft-action` (lihat dokumentasi
JOSS, bagian *Checking that your paper compiles*).

## Wajib sebelum submit (pemblokir)

- [x] **Lisensi open source (OSI)** — MIT (`LICENSE` di root repo).
- [ ] **ORCID dan afiliasi** penulis di header `paper.md`.
- [ ] **Bagian *AI usage disclosure*** — cek kebijakan JOSS terbaru tentang AI generatif dan pastikan pernyataannya akurat.
- [ ] **Verifikasi setiap referensi** di `paper.bib` (penulis, halaman, DOI) dengan halaman penerbit.
- [ ] **Riwayat pengembangan** — repo publik baru dimulai 3 Nov 2026. JOSS menilai *substantial scholarly effort* dan
      riwayat pengembangan terbuka; cek syarat umur/riwayat proyek di dokumentasi JOSS terbaru. Kemungkinan perlu
      menunggu beberapa bulan pengembangan publik (issue, rilis, kontributor/pengguna) sebelum submit.
- [ ] **Lingkup "research software"** — JOSS hanya menerima software dengan penerapan riset. Perkuat dengan bukti
      pemakaian riset (mis. studi paket PHP *nulled*, atau evaluasi yang bisa direproduksi) dan sebutkan di *Statement of need*.

## Sangat disarankan (dinilai reviewer)

- [ ] README dan dokumentasi pengguna dalam **bahasa Inggris** (reviewer JOSS internasional); README Indonesia bisa
      dipertahankan sebagai `README.id.md`.
- [ ] `CONTRIBUTING.md` (cara lapor bug, minta fitur, kirim PR) dan `CODE_OF_CONDUCT.md`.
- [ ] `CITATION.cff` dan rilis ber-DOI (integrasi GitHub ↔ Zenodo) untuk versi yang di-review.
- [ ] **CI** (GitHub Actions di `windows-latest`): build + 100 test pada setiap push, lencana di README.
- [ ] Instruksi menjalankan test untuk reviewer (`dotnet run --project tests/WebGuard.Tests`).
- [ ] Contoh pemakaian yang bisa diulang: proyek demo di `samples/` + hasil yang diharapkan.
- [ ] Angka evaluasi di paper (26,7 s → 3,9 s) disertai cara mengukurnya (skrip benchmark di repo).

## Alur submit

1. Penuhi daftar di atas, buat rilis (mis. v1.1.0) dan arsip Zenodo.
2. Submit di <https://joss.theoj.org/papers/new> dengan URL repo dan cabang yang berisi `paper/paper.md`.
3. Editor memeriksa lingkup → review terbuka di GitHub (biasanya 2 reviewer) → perbaikan → terbit dengan DOI.
