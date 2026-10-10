# Handoff: perbaikan koneksi model dan status matriks TUI

Status: completed, 2026-10-11. Perbaikan kode, suite offline, Doctor live,
smoke TUI/headless, dan audit regresi runtime 108 koordinat sudah lulus.
Hasil eksperimen adalah 48 success dan 60 error; penerimaan scoring tetap
menjadi pekerjaan terpisah.

[Investigasi lanjutan 60 hasil incomplete](../upcoming/HANDOFF_MATRIX_60_INCOMPLETE_ERRORS_V2_2026-10-11.md)
memiliki diagnosis penyebab dan kontrol pembanding. Run tersebut memakai
metrik runtime provisional v2; penerimaan lifecycle TUI tidak menerima skor
final penelitian atau menyelesaikan hasil metode yang belum terkonfirmasi.

## 1. Tujuan dan hubungan dengan handoff lain

Pulihkan konfigurasi model eksperimen pada peluncur TUI dan pastikan progres,
status akhir, jurnal, serta descriptor sesuai artefak eksekusi. Implementasi
rubrik dan kontrol offline tercatat pada
[handoff scoring.v4 yang selesai](../completed/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md).
[Handoff ranking dan oracle](../upcoming/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md)
menangani penerimaan bukti penelitian dan matriks lengkap setelah perbaikan ini.

Bug koneksi ini berada pada peluncur model eksperimen TUI. AI reviewer memakai
resolusi konfigurasi terpisah dan telah berhasil melakukan review langsung.
Ketiadaan profil ranking membuat skor final pending; kondisi itu tidak
membuktikan kegagalan koneksi dan tidak otomatis menghentikan worker matriks.

## 2. Baseline dan bukti langsung

Bagian ini mencatat diagnosis sebelum perbaikan pada 2026-10-10. Hasil sesudah
perbaikan dan validasi ulang setelah DVWA dinyalakan tercatat pada bagian 7.

Diagnosis membandingkan HEAD `ce7941b` dengan tip `runtime-ui` `91f4d0b`.
Regresi peluncuran dan event muncul pada `6b2f35b` tanggal 2026-09-23;
parent `3aa5707` masih meneruskan konfigurasi dan membedakan event parent/child.
Perubahan scoring.v4 terjadi kemudian. Pemeriksaan URL provider sudah ada pada
branch lama; kegagalan sekarang tidak disebabkan aturan containment baru.

Semua pemeriksaan berikut memakai DVWA aktual dan hanya
`openai_compatible` / `deepseek-v4.1-flash`. Smoke yang diminta adalah
`sqli_union`, keamanan low, satu repeat, `hybrid` dan `llm_mutation_only`,
`akg_guided_hybrid`, budget 5, dan empat iterasi. TUI saat ini kehilangan
sebagian pengaturan tersebut pada batas runner.

| Jalur program | Koordinat selesai | Run berhasil | Hasil yang relevan |
| --- | ---: | ---: | --- |
| TUI saat ini, konfigurasi auto | 2/2 | 0/2 | Kedua artefak gagal `LLM_RUNTIME_FAILURE`; model utama kehilangan endpoint. |
| Headless saat ini, auto | 2/2 | 2/2 | Konfigurasi model diteruskan dan koneksi berhasil. |
| Headless saat ini, `json_prompt` | 2/2 | 2/2 | Kontrol pembanding untuk mode struktur branch lama. |
| Peluncur dashboard `runtime-ui`, `json_prompt` | 2/2 | 2/2 | Konfigurasi diteruskan dan koneksi berhasil. |
| Headless `runtime-ui`, `json_prompt` | 2/2 | 1/2 | Mutation-only mencapai terminal dengan hasil metode tidak lengkap; bukan kegagalan endpoint. |

Doctor live saat ini lulus 16/16. Doctor lama lulus 15/16 dengan native auto
karena satu keluaran terstruktur tidak menghasilkan objek; mode yang didukung
`json_prompt` lulus 16/16. Jangan menyimpulkan bahwa setiap hasil metode lama
berhasil atau bahwa semua perbedaan skor merupakan peningkatan model.

Bukti primer: [laporan diagnosis](../../results/validation/runtime-ui-regression-2026-10-10/README.md),
[ringkasan terstruktur](../../results/validation/runtime-ui-regression-2026-10-10/report.json),
[observasi peluncuran TUI](../../results/validation/runtime-ui-regression-2026-10-10/tui-current-live-verified/report.json),
dan [transisi layar](../../results/validation/runtime-ui-regression-2026-10-10/tui-current-live-verified/ui-transitions.json).
TUI saat ini memakai terminal uji Textual dengan worker, HTTP, dan provider
aktual. Peluncur dashboard lama diuji terpisah dari render. Playback terminal
fisik dan matriks lengkap 108 koordinat belum diperiksa.

## 3. Perbaikan wajib

| Masalah | Sumber dan akibat | Perbaikan yang diperlukan |
| --- | --- | --- |
| Konfigurasi model dan eksperimen hilang | `_run_blocking()` pada [tui_mission.py](../../tesis/tui_mission.py) tidak meneruskan `model_configs`, profil/role runtime, kondisi, target metode, serta batas eksekusi secara lengkap. | Gunakan perilaku forwarding headless sebagai referensi; teruskan seluruh konfigurasi yang sudah di-resolve untuk matriks dan single run. |
| Event child mengakhiri atau mereset layar parent | `apply_run_event()` pada [tui_state.py](../../tesis/tui_state.py) memperlakukan lifecycle child seperti lifecycle seluruh matriks. Dua child mereset baris/ID parent; layar akhir hanya menyimpan satu baris. | Pisahkan scope parent dan koordinat; pertahankan identitas, seluruh baris, dan jam parent sampai terminal parent. |
| Status jurnal bertentangan dengan hasil | Peluncur tidak meminta `include_aggregate`, mengabaikan nilai kembali runner, dan menulis succeeded setelah return biasa meskipun semua child error. | Konsumsi agregat otoritatif dari [multi_llm_runner.py](../../evaluation/multi_llm_runner.py); sinkronkan hasil, layar, jurnal, dan status terminal, termasuk kegagalan dan pembatalan. |
| Descriptor tidak aktif | `_open_descriptor()` dan `_close_descriptor()` memakai signature yang tidak sesuai; galat ditelan. | Panggil API [live_runtime.py](../../tesis/live_runtime.py) dengan argumen yang diperlukan dan periksa lifecycle descriptor serta lokasi artefak. |

Galat aktual model eksperimen:

```text
ValueError: openai_compatible provider requires base_url. Set it in config.yaml models.openai_compatible.base_url or OPENAI_COMPATIBLE_BASE_URL environment variable.
```

Catatan panggilan menamai `orchestrator` dan `payload_generator`, dengan model
serta endpoint unknown. Profil pada YAML sebenarnya memiliki endpoint.
`scoring_evaluator.model_profile: openai_compatible` mewarisi URL dan API key
melalui [config_loader.py](../../tesis/config_loader.py). Menambahkan URL duplikat
ke blok scorer tidak memperbaiki kehilangan profil model eksperimen.

## 4. Cakupan implementasi dan invariant

Telusuri pemanggil pada `tesis/tui_mission.py`, `tesis/tui_state.py`,
`tesis/headless.py`, `tesis/live_runtime.py`, `tesis/runtime_journal.py`,
`evaluation/multi_llm_runner.py`, dan `evaluation/runner.py` sebelum mengedit.
Reuse kontrak runner serta konfigurasi bersama yang tersedia; hindari salinan
pengaturan TUI yang berbeda dari headless. Pertahankan facade `tesis.tui` dan
pemilik path `tesis.tui_state.CONFIG_PATH`.

Pertahankan identitas eksperimen, `target_method`, `payload_mode`, repeat,
kondisi, budget, kebijakan stop, runtime role/cache/concurrency, pengaturan
guardrail, dan bukti scoring. Gunakan nama `guardrail_handling`/`guardrail_retry`
pada kode baru dan kompatibilitas nama lama bila boundary membutuhkannya.
Containment tetap aktif. Hanya DVWA serta sembilan metode yang sudah terdaftar
yang boleh digunakan. Kredensial tidak boleh masuk laporan atau capture.

## 5. Kontrol dan penerimaan melalui program

Reproduksi sebelum perbaikan dan simpan artefak, lalu jalankan kontrol yang sama
setelah perbaikan. Kontrol baru ditulis sebelum kode bila diperlukan. Pemeriksaan
semantik atau assertion argumen saja belum menjadi penerimaan koneksi live.

| Kontrol | Hasil yang harus dibuktikan |
| --- | --- |
| Konfigurasi dan Doctor aktual | Profil model utama dan reviewer ter-resolve, Doctor live lulus; pengaturan struktur yang dipilih dicatat. |
| Smoke TUI dan headless dengan YAML sama | Kedua koordinat selesai; endpoint model dikenali, tidak ada kehilangan base_url, dan identitas/kondisi/target/batas pada artefak sesuai pengaturan. Keberhasilan exploit tetap dilaporkan sesuai observasi. |
| Dua child atau lebih | Seluruh baris tetap ada, ID parent tetap, progres dan jam mengikuti parent, terminal child tidak menyelesaikan matriks. |
| Child gagal dan pembatalan | Kegagalan tidak dilabeli sukses; pembatalan tetap cancelled; jumlah selesai/belum dimulai serta artefak parsial tetap tersedia. Pakai kontrol offline yang diberi label untuk menghasilkan kondisi ini secara repeatable. |
| Descriptor dan jurnal | Descriptor aktif selama run, terminal benar sesudahnya, dan observer membaca identitas serta hasil yang sama dengan artefak. |
| Single run | Pengaturan model, role, dan eksperimen diteruskan tanpa regresi pada jalur single. |

Perintah diagnosis yang tersedia, dari root repo:

```bash
.venv/bin/python -m tesis run --dry-run --config results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml
.venv/bin/python -m tesis doctor --config results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml --live --json
.venv/bin/python -m tesis run --headless --mode matrix --config results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml --providers openai_compatible --json
.venv/bin/python -m tesis run
```

TUI membaca `config.yaml` root dan tidak menerima `--config`. Untuk pengujian
interaktif, simpan backup dan hash konfigurasi operator, terapkan smoke yang
sama secara sementara, lalu pulihkan berkas. Harness diagnosis
`results/validation/runtime-ui-regression-2026-10-10/run_tui_smoke.py` juga
tersedia; perintah lengkap ada pada laporan diagnosis. YAML yang dipindahkan
memerlukan `.env` di sampingnya atau environment yang sudah dimuat oleh loader.
Jangan salin key ke YAML atau log.

Harness diagnosis mempertahankan observasi API privat sebelum perbaikan.
Kontrol setelah perbaikan memakai `run_live_acceptance.py` pada paket bukti
baru, dengan descriptor aktual dan signature runner yang dipertahankan.

Simpan bukti perbaikan baru pada `results/validation/tui-model-matrix-fix-2026-10-10/`:
manifest perintah/config/hash, artefak child, agregat, jurnal, descriptor,
event/transisi TUI, capture, dan tabel hasil sebelum/sesudah. Script
`build_report.py` diagnosis mengharapkan bug lama; jangan memakainya sebagai
assertion keberhasilan perbaikan tanpa memperbarui ekspektasi pada paket baru.

## 6. Kriteria selesai

- [x] Konfigurasi model dan seluruh pengaturan eksperimen diteruskan pada TUI matrix/single.
- [x] Lifecycle parent/child, agregat, jurnal, dan descriptor konsisten pada sukses, gagal, dan pembatalan.
- [x] Doctor, smoke live TUI/headless, serta kontrol kegagalan menghasilkan bukti repeatable; skor provisional pada run gagal tidak dilaporkan sebagai hasil diterima.
- [x] Batas terminal fisik yang belum diuji dilaporkan; bila diklaim diterima, lakukan uji terminal aktual dan simpan capture.
- [x] Hasil, perintah, konfigurasi, dan lokasi bukti ditambahkan ke handoff; dokumen dipindahkan ke `docs/completed/` setelah penerimaan di atas lulus.

Perbaikan koneksi tidak melengkapi ranking/oracle. `Srun_final` yang pending
tetap menjadi tanggung jawab handoff kedua.

## 7. Implementasi dan bukti perbaikan

TUI dan headless kini memakai `tesis.headless.run_resolved` untuk menjalankan
konfigurasi yang sudah di-resolved. Fungsi tersebut meneruskan pengaturan model,
role/cache/concurrency, eksperimen, batas eksekusi, guardrail, dan scoring serta
menyiapkan layout artifact, jurnal, dan descriptor. TUI menyimpan hasil runner
dan lokasi artifact; agregat matrix diminta melalui `include_aggregate=True`.
Event lifecycle child tidak lagi mereset identitas, jam, atau baris parent.
Status terminal mengikuti hasil runner, termasuk error dan cancellation.
Descriptor memakai API yang sesuai dan terminalisasi melalui heartbeat sink
mencegah event terakhir mengaktifkan kembali descriptor single run.

Kontrol ditulis sebelum perubahan runtime pada
[`test_tui_model_matrix_runtime_e2e.py`](../../tests/test_tui_model_matrix_runtime_e2e.py).
Baseline menghasilkan delapan kegagalan: descriptor tidak tersedia, identitas
parent hilang, dan agregat tidak disimpan. Setelah perbaikan, delapan kontrol
tersebut lulus, termasuk matrix scheduler aktual dengan child offline yang
gagal atau dibatalkan. Kontrol cancellation membuktikan satu child selesai,
satu belum dimulai, dan artifact parsial tetap tersedia. Kontrol ini tidak
melakukan HTTP atau panggilan provider.

| Pemeriksaan | Hasil | Bukti |
| --- | --- | --- |
| Suite offline lengkap | 2088 passed | [JUnit](../../results/validation/tui-model-matrix-fix-2026-10-10/full-suite-junit.xml) |
| Dry run tiga surface | Lulus; SQLi 24, Access Control 18, Brute Force 12 koordinat payload | [Manifest repeatable](../../results/validation/tui-model-matrix-fix-2026-10-10/dry-runs-repeatable/manifest.json) |
| Doctor live setelah DVWA siap | 16/16 lulus, structured output auto | [Doctor](../../results/validation/tui-model-matrix-fix-2026-10-10/doctor-dvwa-ready-2026-10-11.json) |
| TUI live matrix | 2/2 success, seluruh pemeriksaan lifecycle lulus | [Laporan](../../results/validation/tui-model-matrix-fix-2026-10-10/live-smoke-dvwa-ready-2026-10-11/matrix/report.json) |
| TUI live single | 1/1 success, pengaturan dan observer konsisten | [Laporan](../../results/validation/tui-model-matrix-fix-2026-10-10/live-smoke-dvwa-ready-2026-10-11/single/report.json) |
| Headless live matrix | 2/2 success, containment failures 0 | [Artifact root](../../results/validation/tui-model-matrix-fix-2026-10-10/headless-smoke-dvwa-ready-2026-10-11/) |
| Matrix regresi runtime 108 koordinat | Audit runtime lulus untuk 18 peluncuran; 48 success, 60 error | [Audit](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/audit.json) |
| Integritas bukti matrix | 234 receipt, tanpa hash mismatch; 108 koordinat unik, 108 artifact child, 18 agregat | [Hash ledger](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/hash-ledger.json) |

Perintah yang dapat diulang, dari root repository:

```bash
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
.venv/bin/python results/validation/tui-model-matrix-fix-2026-10-10/prepare_dry_runs.py results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml results/validation/tui-model-matrix-fix-2026-10-10/dry-runs-repeatable
.venv/bin/python -m tesis doctor --config results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml --live --json
.venv/bin/python results/validation/tui-model-matrix-fix-2026-10-10/run_live_acceptance.py results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml results/validation/tui-model-matrix-fix-2026-10-10/live-smoke-dvwa-ready-2026-10-11
.venv/bin/python -m tesis run --headless --mode matrix --config results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml --providers openai_compatible --output-dir results/validation/tui-model-matrix-fix-2026-10-10/headless-smoke-dvwa-ready-2026-10-11 --json
.venv/bin/python results/validation/tui-model-matrix-fix-2026-10-10/run_live_acceptance.py results/validation/runtime-ui-regression-2026-10-10/live-smoke.yaml results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11 --suite
.venv/bin/python results/validation/tui-model-matrix-fix-2026-10-10/audit_matrix_suite.py results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11
```

Gunakan direktori output baru saat mengulang pemeriksaan agar bukti penerimaan
di atas tetap utuh. Manifest suite menyimpan konfigurasi setiap peluncuran,
snapshot harness, dan hash sumber runtime yang benar-benar dijalankan.

Seluruh pemeriksaan live hanya memakai DVWA yang dikonfigurasi dan
`openai_compatible` / `deepseek-v4.1-flash`. Suite 108 menguji dua kondisi,
sembilan metode, tiga security level, dua payload mode, dan satu repeat, dengan
budget 5 dan empat iterasi. Slice `hybrid` berisi 54 koordinat; slice
`llm_mutation_only` berisi 54 koordinat ablation opsional. Suite ini memeriksa
regresi runtime dan tidak menerima ranking/oracle atau skor final penelitian.
Seluruh 18 peluncuran lulus pemeriksaan forwarding, scope event, descriptor,
jurnal, identitas, dan kelengkapan artifact. Status agregat adalah success pada
dua peluncuran dan error pada 16 peluncuran yang memiliki child tidak lengkap.
Layar dan observer menampilkan status error tersebut sesuai artifact.

| Kondisi | Payload mode | Success | Error |
| --- | --- | ---: | ---: |
| `linear_hybrid` | `hybrid` | 17 | 10 |
| `linear_hybrid` | `llm_mutation_only` | 6 | 21 |
| `akg_guided_hybrid` | `hybrid` | 17 | 10 |
| `akg_guided_hybrid` | `llm_mutation_only` | 8 | 19 |

| Target metode | Linear success/error | AKG success/error |
| --- | ---: | ---: |
| `sqli_union` | 4/2 | 5/1 |
| `sqli_error` | 3/3 | 3/3 |
| `sqli_boolean_blind` | 3/3 | 3/3 |
| `sqli_time_blind` | 4/2 | 5/1 |
| `ac_idor` | 0/6 | 0/6 |
| `ac_vertical_escalation` | 0/6 | 0/6 |
| `ac_force_browse` | 0/6 | 0/6 |
| `bf_dictionary` | 6/0 | 6/0 |
| `bf_spray` | 3/3 | 3/3 |

Semua target metode dipilih dan dicoba, tanpa substitusi. Enam puluh child error
berakhir dengan `INCOMPLETE`/`UNSPECIFIED`, tanpa failure class dan tanpa temuan
terkonfirmasi. Setiap child tersebut mencatat satu panggilan LLM yang selesai
dan tidak mencatat kegagalan panggilan LLM. `core/scorer.py` menghasilkan
INCOMPLETE bila tidak ada temuan atau alasan eksplisit; `evaluation/runner.py`
mengisi UNSPECIFIED untuk alasan yang kosong. Penyebab hasil metode belum
diatribusikan. Tidak ada bukti bahwa kehilangan endpoint TUI muncul kembali.

Suite baru mencatat 289 respons HTTP 200 dan 38 respons HTTP 404. Respons 404
hanya tercatat pada SQLi boolean/time blind. Status HTTP tersebut belum cukup
untuk menyimpulkan penyebab hasil metode atau gangguan server DVWA. Skor
provisional pada child error tidak dinyatakan sebagai hasil penelitian diterima.

Harness mengatur `tesis.tui_state.CONFIG_PATH` ke YAML smoke sehingga konfigurasi
operator tidak perlu diganti. Hash `config.yaml` root tetap
`d7682c2f84856793a17a073e83026f16eb7f69b8c0154a297a6485c2da3bec0e`, sama dengan
HEAD. Capture memakai terminal uji Textual dengan worker, HTTP, dan provider
aktual. Input keyboard dan playback terminal fisik belum diuji dan tidak
dinyatakan diterima.

Percobaan Doctor awal dibatasi network sandbox; pengulangan dengan akses
network yang diotorisasi lulus. Percobaan harness live pertama gagal sebelum
matrix menjalankan koordinat karena wrapper observasi menyembunyikan signature
runner. Wrapper diperbaiki dengan `functools.wraps`; bukti percobaan awal tetap
disimpan pada `live-smoke-harness-v1`. Smoke yang lulus dijalankan sebelum
assertion set koordinat dan hash ledger ditambahkan ke harness. Identitas
koordinat smoke diperiksa kembali dari artifact tersimpan. Manifest mencatat
hash versi harness yang benar-benar dijalankan. Smoke dan suite lengkap diulang
setelah pengguna menyalakan DVWA pada 2026-10-11, dengan snapshot harness dan
hash sumber runtime pada manifest. Lima hash sumber runtime sesuai dengan
suite yang telah dijalankan. Scan satu API key terkonfigurasi pada 652 berkas
bukti baru tidak menemukan key tersebut. Pemeriksaan script dan
`git diff --check` juga lulus.

Percobaan suite sebelumnya pada `matrix-suite-108/` berhenti sebelum seluruh
peluncuran selesai. Bukti tersebut tetap disimpan terpisah: 15 laporan
peluncuran dan 91 artifact child, dengan 39 success dan 52 error. Satu child
AKG `ac_force_browse` tidak tercakup laporan peluncuran. Percobaan ini tidak
memiliki audit lengkap dan tidak digabung dengan suite baru. Artifact lama
juga memiliki respons HTTP; hasilnya tidak diatribusikan pada server yang mati.
