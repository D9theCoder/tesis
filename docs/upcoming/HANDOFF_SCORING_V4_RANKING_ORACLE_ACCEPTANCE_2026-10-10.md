# Handoff: profil ranking, oracle DVWA, dan penerimaan penelitian scoring.v4

Status: upcoming, 2026-10-10. Kontrak kode dan kontrol offline sudah diterapkan;
profil penelitian, oracle independen, dan penerimaan matriks lengkap belum
tersedia. Dokumen ini menerima pekerjaan tersisa dari
[handoff implementasi yang selesai](../completed/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md).

## 1. Tujuan dan urutan pekerjaan

Lengkapi sumber pembanding `Smethod` dan bukti oracle untuk klaim Access Control,
Brute Force, serta penggunaan hasil/chain yang memerlukannya. Jalankan matriks
yang diminta dan laporkan komponen beserta `Srun` AI final dari artefak yang
memenuhi kontrak. Selesaikan audit dan layout DOCX aktual sebagai bagian dari
penerimaan laporan.

[Perbaikan koneksi dan lifecycle matriks TUI](../completed/HANDOFF_TUI_MODEL_CONNECTION_AND_MATRIX_RUNTIME_2026-10-10.md)
sudah lulus kontrol offline, smoke live TUI/headless, dan audit runtime 108
koordinat. Hasil eksperimen adalah 48 success dan 60 error. Bukti tersebut belum
menjadi penerimaan final scoring.v4;
persiapan profil ranking dan oracle tetap menjadi pekerjaan handoff ini.

[Handoff investigasi 60 hasil incomplete](HANDOFF_MATRIX_60_INCOMPLETE_ERRORS_V2_2026-10-11.md)
menelusuri penyebab eksekusi pada suite runtime yang memakai metrik provisional
v2. Hasil investigasi itu menjadi masukan bukti; penerimaan ranking, oracle,
dan skor final v4 tetap mengikuti kontrak handoff ini.

Pemilik memilih mode penilai AI karena profil ranking dan oracle aktual belum
ada. AI digunakan sebagai reviewer bukti tersimpan; keputusan ini tidak
mengizinkan evaluator membuat fakta izin, sesi, atau peringkat setelah melihat
hasil eksperimen. Penilaian manusia dan AI tetap menjadi workflow terpisah.

## 2. Empat pekerjaan yang diteruskan

| Todo | Hasil yang harus tersedia | Status awal |
| --- | --- | --- |
| 1. Profil ranking | Sembilan skenario permukaan/keamanan, seluruh metode pembanding, sumber, protokol, budget, hash dan waktu pembekuan sebelum eksekusi. | Belum ada profil penelitian yang lengkap dan dibekukan. |
| 2. Oracle DVWA | Sumber operator independen, kontrol izin/sesi dan hubungan penggunaan, serta binding fixture/run/kandidat/bukti yang memenuhi kontrak. | Belum tersedia untuk klaim penuh yang memerlukannya. |
| 3. Matriks aktual dan tabel skor | 108 koordinat yang diminta, artefak tiap koordinat, receipt AI, alasan pending/gagal/infeasible, serta tabel seluruh komponen dan `Srun`. | Matriks lengkap belum dijalankan; diagnosis terbatas dicatat pada handoff pertama. |
| 4. Penerimaan DOCX aktual | Audit berhash atas teks, warna merah, italic, formula, tabel, objek, serta render Word/LibreOffice dari versi final yang sama. | Isi sebagian sudah diperiksa; perbedaan teks/geometri dan layout aktual belum diterima. |

## 3. Profil ranking dan dasar akademik

Ikuti [kontrak ranking](../completed/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md#4-aturan-pemeringkatan-smethod)
dan [validator scoring_evidence.py](../../evaluation/scoring_evidence.py).
Profil memuat `profile_id`, versi, `fixture_id`, `protocol_version`,
`candidate_budget`, `frozen_at`, hash, serta sumber protokol. Isi sembilan
koordinat: tiga permukaan (`sqli`, `access_control`, `brute_force`) pada keamanan
low, medium, high. Sertakan seluruh metode pembanding pada permukaan yang sama.

Setiap metode mempunyai prasyarat AKG, `fit_predicates`, `planned_request_count`
integer positif, `protocol_refs` yang valid, dan `allowed_plans`. Urutan tetap:
metode layak, kesesuaian observasi tertinggi, kemudian kebutuhan permintaan
referensi terkecil. Metode dengan pasangan terbaik yang sama tetap setara.
Observasi pembanding yang unknown tidak boleh diam-diam membuang kompetitor.
Jumlah permintaan mencakup kontrol wajib pada tujuan dan budget yang sama;
jumlah aktual dari run yang sedang dinilai tidak menentukan ranking awal.

Dasar ranking dapat berupa penelitian terdahulu dan panduan teknis yang
relevan. Catat kutipan, versi sumber, kondisi penelitian, hasil perbandingan,
asumsi pemindahan ke DVWA, dan alasan setiap predikat/protokol. CVE atau advisory
mendukung fakta kerentanan dan prasyarat; bukti satu teknik berhasil belum
menetapkan urutan antarmetode. Hindari urutan universal bila bukti hanya
mendukung kesesuaian pada kondisi tertentu.

Profil yang disusun dari literatur dan telaah ahli dilaporkan sebagai referensi
berbasis literatur. Klaim ranking tervalidasi secara empiris pada fixture ini
memerlukan kontrol pembanding yang relevan pada DVWA aktual, tujuan sama, dan
protokol/budget yang ditetapkan terlebih dahulu. Pisahkan pilot kalibrasi dari
run utama yang akan dinilai; simpan hasil termasuk kegagalan dan kesetaraan.
Jangan membentuk profil dari hasil utama atau memberi referensi evaluator kepada
pemilih metode sebagai arahan baru.

Schema saat ini menerima asal sumber `operator_fixture` atau `offline_control`.
Profil/protokol fixture yang disusun operator dapat merujuk literatur, tetapi
artikel mentah tidak otomatis merupakan attestation fixture. Sumber sintetis
tetap berlabel offline dan tidak dipakai untuk penerimaan live. Jika format
sumber penelitian memerlukan perubahan kode, tulis kontrol kegagalannya sebelum
implementasi dan perbarui kedua metodologi serta arsitektur yang terdampak.

Bekukan profil sebelum keputusan model dieksekusi. Pertahankan snapshot
observasi saat pemilihan, hash profil, sumber pilihan dan alasan/rencana.
`forced`, `deterministic_fallback`, dan `akg_route` tidak dilaporkan sebagai
kemampuan memilih metode oleh LLM. Kontrol positif/negatif harus membedakan
`Smethod` 2, 3, 4 dan ties; kehilangan profil menghasilkan pending/null bagi
pilihan layak, bukan skor nol atau peringkat buatan AI.

## 4. Oracle independen dan atribusi bukti

Ikuti [kontrak bukti](../completed/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md#6-kontrak-bukti-yang-harus-tersedia)
serta [verifier](../../foundation/verifier.py).

| Kelompok | Sumber yang diperlukan | Kontrol wajib |
| --- | --- | --- |
| Access Control | Aturan izin operator: principal/peran atau pemilik, objek/aksi, keputusan akses, fixture serta sesi yang sama dengan bukti respons/efek. | Akses yang diizinkan dan ditolak; sesi berizin, objek/principal salah, dan visibilitas tanpa pelanggaran izin tidak memperoleh konfirmasi penuh. |
| Brute Force | Validitas kredensial dan identitas sesi baru yang berasal dari kandidat, terpisah dari sesi awal framework. | Marker sukses tanpa sesi, kredensial ditolak, sesi lama, dan sesi milik identitas lain tidak memperoleh konfirmasi penuh. |
| Penggunaan hasil dan chain | Bukti sumber, konsumsi material sumber, konfirmasi tujuan, edge/prasyarat dan urutan kejadian yang terkait. | Salah kandidat/kunjungan/hash, sumber offline pada run live, route siap tanpa konsumsi, atau dua keberhasilan tanpa hubungan tidak memperoleh kredit penuh. |

Attestation mengikat identitas run/eksekusi, fixture, protokol, metode, visit,
kandidat, hash bukti, serta kontrol pembanding. Teks respons, verdict agent, dan
pendapat AI tidak menciptakan sumber oracle. Simpan fingerprint aman; jangan
menaruh password, cookie, token, atau material autentikasi mentah pada laporan.

Audit kandidat harus memakai respons/verifier milik kandidat yang dieksekusi.
Tingkat 4 payload/exploit memerlukan penggunaan dan konfirmasi tujuan yang
terkait. Kandidat sumber dari metode sebelumnya tidak dipindahkan ke penyebut
atau skor metode final. Keterjangkauan skor dilaporkan per skenario; bila DVWA
tidak menyediakan model izin yang diperlukan, laporkan keterbatasan tersebut
tanpa mengubah respons parsial menjadi bukti penuh.

## 5. Gerbang validasi dan matriks yang diminta

Sebelum run utama, periksa AKG, prasyarat, profil, schema prompt/parsing,
validasi payload, routing chain, containment, dan kelengkapan artefak. Jalankan
dry run setiap permukaan dan kontrol E2E kontrak yang relevan. Simpan perintah,
config/hash, hasil yang diharapkan/diamati, serta artefak repeatable. Pengujian
offline dan mock tetap dibedakan dari HTTP/provider aktual.

```bash
.venv/bin/python -m pytest -q tests/test_scoring_evidence_v4_e2e.py tests/test_scoring_remediation_e2e.py tests/test_thesis_scoring_e2e.py --junitxml=results/validation/scoring-evidence-v4/focused.xml
.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml
.venv/bin/python -m tesis run --dry-run --config results/validation/scoring-evidence-v4/config-sqli.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/scoring-evidence-v4/config-access_control.yaml
.venv/bin/python -m tesis run --dry-run --config results/validation/scoring-evidence-v4/config-brute_force.yaml
```

Konfigurasi dry run lama memuat profil/oracle kosong dan hanya menjadi baseline.
Siapkan konfigurasi penerimaan dengan profil/oracle aktual untuk tiap koordinat.
Setelah gerbang lulus, jalankan matriks melalui program; headless memakai:

```bash
.venv/bin/python -m tesis run --headless --mode matrix --config PATH --providers openai_compatible --json
```

`PATH` merupakan YAML penerimaan yang sudah disiapkan. TUI memakai
`.venv/bin/python -m tesis run` dengan `config.yaml` root setelah handoff pertama
diterima. Hanya provider `openai_compatible` dan model DeepSeek yang dikonfigurasi
(`deepseek-v4.1-flash` pada diagnosis) digunakan untuk eksperimen dan reviewer.
Pertahankan sembilan target metode, tiga keamanan, dua kondisi, dua mode payload,
dan satu repeat. Mode mutation-only tetap ablasi opsional.

| Kondisi | Mode payload | Koordinat diminta | Penerimaan awal |
| --- | --- | ---: | --- |
| `linear_hybrid` | `hybrid` | 27 | Belum dijalankan sebagai matriks lengkap. |
| `akg_guided_hybrid` | `hybrid` | 27 | Belum dijalankan sebagai matriks lengkap. |
| `linear_hybrid` | `llm_mutation_only` | 27 | Belum dijalankan sebagai matriks lengkap. |
| `akg_guided_hybrid` | `llm_mutation_only` | 27 | Belum dijalankan sebagai matriks lengkap. |

Total 108 koordinat. Smoke diagnostik terpisah tidak mengisi penerimaan rencana
ini. Bila sebuah koordinat infeasible atau gagal, simpan alasannya dan seluruh
bukti; jangan mengganti metode diam-diam atau mengulang untuk memilih hasil bagus.
Dengan satu repeat, stabilitas antar repeat tetap null.

Review AI dilakukan dari artefak eksekusi tersimpan melalui
[thesis_scoring.py](../../evaluation/thesis_scoring.py); reviewer bukan model
utama dan bukan oracle fixture. `model_profile: openai_compatible` mewarisi
endpoint/key dari profil model pada loader; tidak perlu URL scorer duplikat.
Review smoke yang telah disetujui pemilik berhasil dengan satu panggilan dan
satu nilai kandidat 3, tetapi `Smethod` masih `ranking_unavailable` dan
`Srun_final` null. Hash sumber tetap utuh.

Laporkan satu baris setiap koordinat/workflow dengan kondisi, metode target dan
metode aktual/fallback, keamanan, payload mode, repeat, status eksekusi,
`Smethod`, `Spayload`, `Sexploit`, `Schain`, `Soutput`, `Srun_final`, alasan
pending/unassessable, dan path receipt. Nilai provisional diberi label terpisah.
Ringkasan menyertakan jumlah direncanakan, selesai, gagal, infeasible, final,
dan pending; vektor manusia/AI serta versi rubrik tidak digabung.

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
```

## 6. Penerimaan DOCX dan dokumen referensi

Audit DOCX lama berlaku hanya pada hash yang tercatat. Versi
`2512e7be0e78b8a35c5cc56f6c0859f6b85fa115358e3a108dedf0c8c3fddf65`
lulus audit revisi bahasa, warna dan italic. Audit versi
`478ce522ac8e28085000fc419020c40969f1d785f2f65cb8939b073f0ea3474e`
menemukan kalimat baru pada paragraf 82 dan perbedaan geometri; layout versi
tersebut belum dirender. Render Word 17 halaman adalah versi sebelumnya.

Periksa dan jelaskan perbedaan pada versi aktual, lalu audit ulang berdasarkan
hash final. Pertahankan tujuh tabel dan 35 contoh, formula/nilai ilustratif,
objek tertanam, teks di luar revisi yang disetujui, format merah/italic serta
geometri yang diterima. Render Word/LibreOffice dan tinjau seluruh tabel pada
berkas dengan hash yang sama. Kegagalan interop WSL atau ekspor yang berhenti
merespons tetap dilaporkan sebagai penerimaan visual yang belum selesai.

Ulangi audit yang tersedia:

```bash
.venv/bin/python results/validation/scoring-evidence-v4/audit_current_docx.py
```

Pastikan generator [rubric_document.py](../../evaluation/rubric_document.py)
mengacu pada handoff implementasi di `docs/completed/` dan handoff penerimaan
ini. Jangan mengubah DOCX sumber hanya untuk memindahkan path handoff.
Sinkronkan [scorebook](../reference/thesis_scoring.md),
[metodologi Inggris](../reference/summary_en.md),
[metodologi Indonesia](../reference/summary_id.md), serta
[arsitektur](../reference/architecture.md) jika kontrak atau metodologi berubah.

## 7. Kriteria selesai dan paket bukti

- [ ] Todo 1: sembilan profil lengkap, dasar ranking ditelaah, kontrol pembanding tercatat, hash dan waktu pembekuan valid sebelum keputusan eksperimen.
- [ ] Todo 2: oracle independen serta kontrol negatif/positif memenuhi binding; batas skor yang tidak dapat dicapai dilaporkan per skenario.
- [ ] Todo 3: semua 108 koordinat mempunyai hasil atau alasan eksplisit; review AI, pending, komponen dan komposit dapat diaudit serta dihitung ulang dari sumber immutable.
- [ ] Todo 4: audit DOCX aktual dan render visual berhash sama diterima; dokumen referensi konsisten dengan status dan kontrak aktual.
- [ ] Tingkat 4 payload/exploit, chain, output dan pemisahan workflow dibuktikan sesuai konteks metode final; hasil sintetis tidak disebut penerimaan live.
- [ ] Artefak dan receipt historis tetap utuh; perbandingan tidak mencampur versi rubrik/profil, dan pending tidak berubah menjadi nol.

Paket baru berada di `results/validation/scoring-v4-live-acceptance-2026-10-10/`:
manifest, sumber/profil frozen beserta hash, oracle dan kontrol, artefak per
koordinat, receipt AI, audit binding/aritmetika, tabel hasil, DOCX backup/hash,
audit dan render visual. Paket lama pada `results/validation/scoring-evidence-v4/`
tetap menjadi riwayat baseline. Pindahkan handoff ini ke `docs/active/` saat
implementasi dimulai, lalu `docs/completed/` setelah penerimaan terpenuhi.

## 8. Riwayat preflight dan audit yang dipindahkan

Bagian berikut mempertahankan catatan dari handoff asal; ini bukan hasil baru
atau bukti bahwa matriks lengkap telah dijalankan. Ketiadaan profil/oracle
merupakan gap penerimaan final, bukan penyebab otomatis worker berhenti.

### Pemeriksaan lanjutan dan matriks yang diminta (2026-10-10)

Konfigurasi yang di-*resolve* memakai mode penilai AI, rubrik `scoring.v4`,
provider `openai_compatible`, dan model `deepseek-v4.1-flash` untuk peran model
serta penilai. Kredensial model tersedia melalui `.env`. Target DVWA pada
`http://172.19.48.1/dvwa` mengembalikan HTTP 302 ke halaman *login* ketika
diakses di luar sandbox jaringan alat. Pemeriksaan awal dari dalam sandbox
gagal terhubung; kegagalan itu bukan bukti bahwa target operator mati.

Matriks yang diminta telah didaftarkan dengan sembilan metode, tiga tingkat
keamanan, dua kondisi eksperimen, mode `hybrid` dan `llm_mutation_only`, serta
satu pengulangan. Mode kedua adalah ablasi opsional. Seluruh 108 koordinat rencana lengkap
berstatus belum dijalankan. Pada preflight ini pelaksana menunda penerimaan
utama karena profil ranking dan sumber oracle independen belum ada; ini bukan
larangan otomatis aplikasi dan bukan bukti matriks berhenti saat berjalan. Mode penilai AI tidak menggantikan
kedua sumber tersebut; nilai final `Smethod` bagi pilihan layak serta komposit `Srun` tetap pending
tanpa profil yang dibekukan sebelum eksekusi. Diagnosis live yang dilakukan
setelah preflight ini dicatat pada handoff perbaikan TUI.

| Kondisi | Mode payload | Koordinat direncanakan | Run selesai | `Srun` final |
| --- | --- | ---: | ---: | --- |
| `linear_hybrid` | `hybrid` | 27 | 0 | `null` |
| `akg_guided_hybrid` | `hybrid` | 27 | 0 | `null` |
| `linear_hybrid` | `llm_mutation_only` | 27 | 0 | `null` |
| `akg_guided_hybrid` | `llm_mutation_only` | 27 | 0 | `null` |

[Rencana koordinat dan pemeriksaan konfigurasi](../../results/validation/scoring-evidence-v4/requested-matrix-preflight.json)
dapat dibuat ulang dengan `.venv/bin/python results/validation/scoring-evidence-v4/plan_requested_matrix.py`.
Pemeriksaan ini tidak mengirim permintaan eksploitasi atau panggilan provider.

Suite offline terkini lulus dengan 2.080 tes, nol kegagalan dan nol *skip*,
melalui `.venv/bin/python -m pytest -q --junitxml=results/validation/junit.xml`.
Tiga *dry run* yang mengarah ke konfigurasi `config-sqli.yaml`,
`config-access_control.yaml`, dan `config-brute_force.yaml` di direktori bukti
`scoring-evidence-v4` juga lulus dengan masing-masing 12, 9, dan 6 koordinat
payload. [JUnit](../../results/validation/junit.xml) menyimpan hasil suite.
Pemeriksaan tersebut tidak merupakan validasi DVWA atau provider secara langsung.
[Manifest pemeriksaan terkini](../../results/validation/scoring-evidence-v4/current-validation-manifest.json)
mencatat perintah, konfigurasi, hasil yang diharapkan dan diamati, serta hash
artefak utama.

Audit ulang DOCX saat ini memakai hash
`478ce522ac8e28085000fc419020c40969f1d785f2f65cb8939b073f0ea3474e`.
Ketujuh tabel masih memuat 35 contoh, dan 126 paragraf revisi tetap memenuhi
teks, warna merah, serta *italic* yang dicatat. Namun, paragraf indeks 82
memiliki kalimat penjelasan oracle baru di luar revisi terdahulu. Lebar satu
*table grid* berubah dibandingkan salinan sebelum revisi. Pemeriksaan isi
tersebut sengaja belum dinyatakan lulus penuh. [Audit DOCX saat ini](../../results/validation/scoring-evidence-v4/current-docx-audit.json)
dapat diulang dengan `.venv/bin/python results/validation/scoring-evidence-v4/audit_current_docx.py`.
Panggilan Word dalam sandbox terkena galat interop WSL `UtilBindVsockAnyPort`.
Di luar sandbox, Word dapat membuka berkas, tetapi dua percobaan ekspor PDF
berhenti merespons. Proses Word otomatis dari percobaan tersebut dihentikan dan
berkas sementara dibersihkan; sesi Word interaktif pemilik tidak disentuh.
Layout visual file sekarang belum terverifikasi.
