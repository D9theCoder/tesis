# Handoff: investigasi 60 hasil incomplete pada matriks runtime

Status: upcoming, 2026-10-11. Analisis awal artifact sudah tersedia; penyebab
setiap hasil, perbaikan yang diperlukan, dan validasi pembanding belum selesai.

Empat puluh enam retry incomplete dari matriks pengganti scoring.v4 adalah
cohort terpisah pada [handoff bukti v4](../completed/HANDOFF_SCORING_V4_REMAINING_EVIDENCE_2026-10-11.md).

**Catatan metrik: hasil run ini memakai metrik runtime provisional
`scoring.v2`, bukan skor final `scoring.v4`.** Konfigurasi evaluasi menyebut v4,
tetapi receipt runtime dan composite masih diberi label
`historical_provisional_scoring.v2`. Semua 108 artifact berstatus
`pending_review`, tanpa `Srun_final` dan tanpa receipt review AI. Panggilan LLM
yang tercatat adalah `payload_generator`. Investigasi ini harus membedakan
hasil eksekusi metode dari masalah penilaian provisional.

## 1. Tujuan dan batas pekerjaan

Telusuri seluruh 60 child yang berakhir `INCOMPLETE/UNSPECIFIED`. Tentukan
apakah hasil berasal dari prasyarat atau fixture DVWA, payload yang tidak
efektif, bug agent/verifier, bukti yang tidak lengkap, atau kegagalan provider
yang benar-benar tercatat. Bedakan hasil negatif yang sah dari eksperimen yang
belum menjalankan pemeriksaan yang diperlukan.

[Handoff perbaikan TUI](../completed/HANDOFF_TUI_MODEL_CONNECTION_AND_MATRIX_RUNTIME_2026-10-10.md)
sudah selesai untuk forwarding konfigurasi, lifecycle, dan konsistensi observer.
[Handoff ranking dan oracle](../completed/HANDOFF_SCORING_V4_RANKING_ORACLE_ACCEPTANCE_2026-10-10.md)
tetap memiliki profil penelitian, oracle independen, dan penerimaan skor final.
Jangan menganggap ketiadaan ranking atau skor chain final sebagai penyebab
gagalnya probe tanpa hubungan kausal yang dibuktikan.

Hanya DVWA, tiga surface, dan sembilan metode yang terdaftar yang boleh diuji.
Pertahankan containment serta `experiment_condition`, `target_method`,
`payload_mode`, dan `repeat_index`. Jangan melonggarkan verifier agar hasil
terlihat berhasil. Bila DVWA atau fixture tidak mendukung suatu metode,
nyatakan infeasible dengan alasan dan bukti.

## 2. Baseline dan bukti yang dibekukan

Suite baru berisi 108 koordinat: dua kondisi, sembilan metode, tiga security
level, dua payload mode, satu repeat, budget 5, dan empat iterasi. Hanya
`openai_compatible` / `deepseek-v4.1-flash` yang digunakan. Hasilnya 48 success
dan 60 error. Audit runtime lulus pada 18 peluncuran, dengan dua agregat success
dan 16 agregat error; containment failures berjumlah nol.

| Target metode | Linear error | AKG error | Total error |
| --- | ---: | ---: | ---: |
| `sqli_union` | 2 | 1 | 3 |
| `sqli_error` | 3 | 3 | 6 |
| `sqli_boolean_blind` | 3 | 3 | 6 |
| `sqli_time_blind` | 2 | 1 | 3 |
| `ac_idor` | 6 | 6 | 12 |
| `ac_vertical_escalation` | 6 | 6 | 12 |
| `ac_force_browse` | 6 | 6 | 12 |
| `bf_dictionary` | 0 | 0 | 0 |
| `bf_spray` | 3 | 3 | 6 |
| **Total** | **31** | **29** | **60** |

Dari 60 error, 20 memakai `hybrid` dan 40 memakai `llm_mutation_only`.
Gunakan 48 child success sebagai kontrol pembanding. Slice mutation-only
adalah ablation opsional; kondisi utama tetap hybrid.

Bukti primer berada pada
`results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/`:

- [Manifest konfigurasi, snapshot harness, dan hash runtime](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/manifest.json).
- [Audit koordinat dan lifecycle](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/audit.json)
  serta [234 receipt hash](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/hash-ledger.json).
- [Analisis awal](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/failure-analysis/report.md),
  [ringkasan terstruktur](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/failure-analysis/summary.json),
  dan [analyzer offline](../../results/validation/tui-model-matrix-fix-2026-10-10/matrix-suite-108-dvwa-ready-2026-10-11/failure-analysis/analyze_failure_causes.py).

Hash `config.yaml` root tetap
`d7682c2f84856793a17a073e83026f16eb7f69b8c0154a297a6485c2da3bec0e`.
HEAD saat pemeriksaan wrap-up adalah
`ce7941b988af019b287a2af9e31798786d6175ae`; manifest eksekusi tidak mencatat
base HEAD. Gunakan hash sumber di manifest untuk mengikat perilaku runtime.
Percobaan lama `matrix-suite-108/` hanya memiliki 15 laporan dan 91 artifact
child, termasuk satu child yang tidak tercakup laporan. Simpan terpisah dan
jangan gabungkan dengan suite lengkap yang baru.

## 3. Temuan awal dan hal yang belum terbukti

Seluruh 60 error mencatat satu panggilan payload generator yang selesai,
keluaran valid, dan tidak memiliki failure record provider. Semua target metode
dipilih dan dicoba. Tidak ada bukti kegagalan transport/auth provider pada
cohort ini, tetapi koneksi berhasil tidak membuktikan kualitas payload.

Semua run error berhenti melalui `target_method_complete`, setelah iterasi 2
dari batas 4. Tidak ada temuan atau outcome terkonfirmasi: 54 keputusan verifier
berupa `not_confirmed`, enam berupa `unverified`. Scorer menghasilkan
INCOMPLETE dan runner mengisi UNSPECIFIED karena alasan eksplisit tidak
tersedia. Label error tersebut belum merupakan diagnosis penyebab.

| Kelompok | Bukti awal | Investigasi berikutnya |
| --- | --- | --- |
| Access Control, 36 error | Login agent memakai konteks admin; kontrol otorisasi independen belum memadai. Force-browse mencatat ketiadaan kontrol izin. | Periksa kelayakan endpoint dan fixture, principal/role pembanding, ownership objek, precondition, serta oracle izin. Jangan menyimpulkan semua 36 disebabkan satu bug tanpa kontrol pembanding. |
| Brute Force spray, 6 error | Tidak ada login yang terkonfirmasi. | Bandingkan kandidat, cara pengiriman, session, respons, dan verifier dengan child hybrid yang berhasil pada koordinat sepadan. |
| Boolean-blind SQLi, 6 error | Kondisi tidak cukup repeatable atau branch exploit tidak terverifikasi. | Periksa pasangan true/false, baseline, pemetaan kandidat, gate probe, serta validitas semantik metode. |
| Time-blind SQLi, 3 error | Probe statis menunjukkan delay; kandidat exploit tidak mencapai perbedaan timing yang diperlukan. | Periksa kandidat, parameter, encoding, validasi, dan baseline timing; pisahkan payload tidak efektif dari masalah pengukuran. |
| Error-based SQLi, 6 error; UNION, 3 error | Tidak ada sinyal ekstraksi yang memenuhi verifier. | Bandingkan payload dan respons dengan kontrol statis serta child berhasil; periksa parser/verifier tanpa menurunkan syarat konfirmasi. |

Sebanyak 327 response row memakai origin dan route yang diharapkan: 289 HTTP
200 dan 38 HTTP 404. Semua 404 berada pada SQLi blind dan cocok dengan predicate
missing-ID yang diterima verifier. Status ini bukan bukti endpoint hilang atau
server mati.

Sembilan child error hanya memiliki bukti probe tanpa receipt kandidat yang
terhubung. Kandidat dihasilkan untuk tahap exploit tetapi tidak mencapai
eksekusi exploit yang tercatat. Telusuri gate, provenance, dan pencatatan sebelum
menyalahkan kualitas payload. Default `Spayload=0` pada bukti yang tidak
terhubung harus dibedakan dari skor nol yang dibuktikan. Runtime v2 mengambil
nilai maksimum kandidat; review v4 merupakan alur terpisah.

Sumber yang perlu ditelusuri: [session](../../foundation/session_manager.py),
[agent Access Control](../../agents/access_control/),
[agent SQLi](../../agents/sqli/), [agent Brute Force](../../agents/brute_force/),
[update evidence](../../agents/state_utils.py),
[verifier](../../foundation/verifier.py),
[chain routing](../../core/chaining_coordinator.py),
[scorer](../../core/scorer.py), dan [runner](../../evaluation/runner.py).

## 4. Urutan investigasi dan kontrol

1. Reconcile 60 execution ID terhadap 108 koordinat, artifact child, agregat,
   dan hash. Buat ledger per child: kandidat valid/ditolak, probe/exploit,
   candidate ID, verifier, prasyarat, stop reason, panggilan provider, status,
   serta penjelasan yang didukung bukti. Jangan menulis secret atau session.
2. Telusuri jalur kode untuk setiap kelompok. Bedakan dugaan dengan penyebab
   yang dapat direproduksi. Catat stage yang tidak tercapai serta apakah hasil
   negatif sah, fixture infeasible, evidence gap, bug kode, atau kandidat tidak
   efektif. Jangan memaksakan atribusi provider ketika transport normal.
3. Sebelum mengubah kode, tulis kontrol E2E yang menangkap kegagalan konkret.
   Bekukan konfigurasi dan kandidat tersimpan. Replay offline harus mencatat
   nol panggilan provider dan mengikat hasil ke hash sumber artifact.
4. Untuk Access Control, gunakan oracle independen dan principal pembanding
   yang sesuai pada DVWA. Untuk SQLi/Brute Force, bandingkan kandidat tersimpan
   dengan seed statis pada koordinat sepadan. Kontrol positif dan negatif harus
   independen dari klaim agent yang dinilai.
5. Bila perlu rerun live, luluskan validasi inti dan dry run per surface terlebih
   dahulu. Pertahankan provider compatible yang sama, kondisi, target metode,
   level, mode, repeat, budget, dan kebijakan stop. Ubah satu faktor untuk setiap
   kontrol kausal; simpan hasil pada direktori baru di `results/`.
6. Perbaiki penyebab yang dibuktikan, termasuk alasan terminal yang hilang bila
   relevan. Pertahankan artifact lama dan catat perbedaan sebelum/sesudah.
   Jangan mengubah run negatif menjadi success hanya karena eksekusi selesai.

## 5. Kriteria selesai

- [ ] Semua 60 child memiliki atribusi berbukti atau unresolved yang eksplisit,
  lengkap dengan execution ID dan hubungan ke koordinat sumber.
- [ ] Kelayakan tiga metode Access Control dan kontrol otorisasi independen
  diuji; metode yang tidak layak ditandai dengan alasan yang dapat diperiksa.
- [ ] Sembilan child probe-only ditelusuri sampai gate dan provenance kandidat;
  missing evidence dibedakan dari payload berkualitas rendah.
- [ ] Perbedaan payload/model, agent/verifier, fixture, dan provider transport
  diuji melalui kontrol yang sesuai, dengan hasil negatif tetap dilaporkan.
- [ ] Alasan terminal spesifik tersedia atau keterbatasan atribusinya dinyatakan;
  UNSPECIFIED tidak dijadikan kesimpulan kausal.
- [ ] Perubahan yang diperlukan lulus kontrol E2E serta menghasilkan perintah,
  konfigurasi, hash, dan artifact yang repeatable. Check yang offline, live,
  belum diuji, atau blocked dilaporkan terpisah.
- [ ] Semua tabel mempertahankan label metrik provisional v2. Penerimaan v4,
  ranking, oracle, serta skor chain/final tetap mengikuti handoff pemiliknya.

Pindahkan dokumen ini ke `docs/active/` ketika investigasi dimulai, lalu ke
`docs/completed/` setelah kriteria di atas dipenuhi dan batas unresolved
dilaporkan secara eksplisit.
