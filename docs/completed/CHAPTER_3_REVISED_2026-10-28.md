# BAB III METODOLOGI PENELITIAN (revisi turunan, 2026-10-28)

> **Status dokumen.** Ini adalah **dokumen revisi turunan**, bukan pengganti
> berkas sumber `bab 3 only.docx`. Berkas DOCX sumber dipertahankan byte-per-byte.
> Angka dan tabel rubrik mengikuti kontrak **scoring.v4** di
> `docs/reference/thesis_scoring.md`; tabel lama pada DOCX tidak lagi menjadi
> acuan. Figur 3.1–3.4 direvisi secara konseptual pada bagian akhir dokumen.
> Klaim pada dokumen ini adalah rancangan dan batas bukti, bukan klaim hasil
> eksperimen live.

> **Catatan arsip (2026-10-29).** Dokumen ini dipindahkan ke `docs/completed/`
> atas arahan pemilik. Lokasi arsip tidak menyatakan bahwa prasyarat eksperimen
> atau pemeriksaan visual DOCX telah selesai. Keputusan terbaru untuk dokumen
> gabungan tercatat pada [handoff rekonsiliasi](../active/HANDOFF_COMBINED_THESIS_DOCX_RECONCILIATION_2026-10-29.md),
> termasuk pemilihan metode oleh model pada eksperimen utama, target manual
> untuk diagnostik, dan tidak memasukkan Template ke DOCX gabungan.

## 3.1 Kerangka Pikir Penelitian

Penelitian ini menggunakan lingkungan eksperimen terkontrol (sandbox) untuk
mengembangkan dan mengevaluasi framework autonomous penetration testing berbasis
Large Language Model (LLM) pada Damn Vulnerable Web Application (DVWA).
Permasalahan utamanya adalah ketidakstabilan free-form LLM reasoning ketika
model harus memilih metode, menyesuaikan strategi terhadap observasi,
menghasilkan payload, dan beradaptasi setelah kegagalan.

Penelitian mengusulkan **static pre-validated Attack Knowledge Graph (AKG)**
sebagai struktur pengetahuan yang membatasi ruang keputusan. AKG memuat surface,
method, outcome, edge chain, prasyarat berbasis observasi, dan payload-generation
profile. LLM tidak membangun graph atau agent saat runtime; LLM memilih metode
yang tersedia dan menghasilkan kandidat payload di dalam batasan profil.

Kontribusi yang diukur dipisahkan menjadi dua pertanyaan yang tidak boleh
dicampur:

1. **Blok pemilihan (selection):** `target_method=None`. Model memilih metode
   dari daftar yang diizinkan. Hanya keputusan berlabel `decision_origin=model`
   yang dapat dipakai untuk menilai pemilihan oleh model.
2. **Blok cakupan metode (forced):** setiap metode terdaftar dijalankan sebagai
   koordinat eksplisit. Blok ini menilai agen dan payload per metode, tetapi
   **tidak** membuktikan kemampuan model memilih metode.

Kondisi utama tetap `linear_hybrid` dan `akg_guided_hybrid` dengan payload
`hybrid`. `static_only`, mutation-only ketat, dan Template adalah ablasi/kontrol.
Linear berarti **tidak dipandu AKG untuk pemilihan metode dan routing chain**;
Linear tetap memakai batas scope, payload profile, validator, kontrol, dan rubrik
yang sama. Perbandingan utama karena itu adalah **efek gabungan workflow**, bukan
efek terisolasi prompt pemilihan.

Variabel bebas: kondisi eksperimen, model/provider, tingkat keamanan DVWA,
permukaan kerentanan, metode (pada blok forced), dan mode payload (ablasi).
Variabel terikat: kualitas pemilihan metode, kualitas payload, hasil eksploitasi,
hasil chain, kualitas output/guardrail, konsistensi, dan biaya. Variabel kontrol:
fixture dan protokol yang dibekukan, AKG, static agent, seed, prompt/schema,
anggaran kandidat, kontrol deteksi/verifikasi, pengulangan, dan rubrik v4.

## 3.2 Tahapan Penelitian

Tahapan penelitian yang benar adalah:

1. **Preflight offline** — validasi konfigurasi, kompilasi graph, cek kontrak
   payload per mode, cek registry AKG/template, dan cek manifest prompt/schema.
   Dry run **tidak** membuktikan DVWA siap, sesi valid, level sesuai, atau
   provider dapat dipanggil.
2. **Freeze input dan epoch** — bekukan config, profil ranking, oracle, jadwal
   harga token, versi policy/prompt/schema, hash sumber kode, fixture, dan
   protokol. Perubahan apa pun setelah freeze memulai epoch baru; hasil lama
   tidak boleh diganti atau dilabeli ulang.
3. **Eksekusi dua blok** — selection dan forced dijalankan sebagai blok terpisah,
   minimal tiga repetisi per koordinat, pada fixture dan protokol yang sama.
4. **Review** — artefak eksekusi tetap immutable dan skor runtime tetap
   *provisional* `scoring.v2`. Review Human/AI menghasilkan receipt final v4
   terpisah; reviewer tidak menjalankan ulang DVWA atau provider serangan.
5. **Analisis** — hanya receipt final yang kompatibel digabung; semua koordinat
   planned, error, pending, dan unassessable tetap dilaporkan.

Kriteria transisi: desain AKG siap bila node/edge/precondition/profile tervalidasi;
implementasi siap bila preflight offline lulus; eksperimen siap bila freeze input
dan readiness live lulus; analisis dimulai hanya setelah jumlah repetisi terpenuhi
dan receipt final tersedia atau alasan pending tercatat.

## 3.3 Preliminary Experiment dan Validasi Awal

Validasi awal mencakup unit test deterministik, pemeriksaan registry AKG,
pemeriksaan manifest prompt/schema, serta dry run offline per permukaan. Dry run
memeriksa kontrak tiap mode:

- `static_only`/`hybrid`: seed exploit/bypass kanonik valid dan snapshot kontrol
  deteksi dapat dibekukan; probe tidak masuk antrean exploit.
- `llm_mutation_only`: seed hanya merupakan **input**; kegagalan generator atau
  validator tidak boleh menghidupkan seed sebagai kandidat.
- `llm_template`: registry template netral untuk metode/level harus ada atau
  memiliki limitasi eksplisit; template bukan payload kerja dan tidak boleh
  dieksekusi.

Dry run tidak boleh mengganti seed statis menjadi keluaran model pada mode ketat.

## 3.4 Perancangan Attack Knowledge Graph

AKG statis memuat surface node (`sqli`, `access_control`, `brute_force`), method
node (empat SQLi, tiga Access Control, dua Brute Force), confirmed/outcome node,
dan chain edge. Setiap method memiliki prasyarat observasi, misalnya
`error_messages_enabled`, `response_diff_detectable`,
`response_delay_measurable`, `object_ids_enumerable`, dan `no_rate_limit`.

**Perubahan metodologis penting:** penemuan endpoint **bukan** bukti prasyarat.
Fakta observasi disimpan append-only dengan sumber, kontrol/bukti, metode,
kunjungan, principal/sesi, fixture, dan waktu. Status saat ini diturunkan menjadi
`true`, `false`, atau `unknown`; `unknown` dan kegagalan transport tidak boleh
diperlakukan sebagai `false`. Nilai `true` lama tidak boleh menghapus bukti
negatif baru; riwayat tetap utuh dan pembaca menampilkan status turunan.

Metode hanya layak bila prasyaratnya terbukti. Target eksplisit yang tidak layak
tetap mempertahankan identitasnya dan dicatat `false`/`unknown`/fixture, bukan
diam-diam diganti metode lain. Linear melihat daftar metode kanonik permukaan;
AKG-guided boleh memfilter memakai himpunan layak. Setelah pemilihan, kedua
kondisi memakai gate scope/bukti yang sama.

## 3.5 Static Method Agents dan Payload Candidate Queue

Static method agents tidak dibuat atau diubah LLM. LLM hanya memengaruhi
pemilihan metode dan kandidat payload yang dibatasi profil. Antrean kandidat
berisi **hanya** kandidat exploit/bypass tervalidasi; probe deteksi berada di
snapshot kontrol terpisah.

Setiap kunjungan memiliki satu anggaran kandidat exploit/bypass yang sama untuk
semua asal (static seed, mutasi model, Template, chain-derived). Kontrol deteksi
dan kontrol verifikasi memiliki anggaran sendiri; jumlah request/retry fisik
bukan jumlah kandidat. Kandidat dicatat pada lifecycle append-only:
`generated`, `valid`, `queued`, `executed`, `stopped_before_execution`,
`budget_excluded`, `rejected`, beserta alasan dan bukti. Kandidat yang tervalidasi
tetapi tidak dieksekusi tidak boleh diberi hasil model atau dianggap kegagalan
negatif.

Eksekusi kandidat memerlukan request exploit/bypass milik kunjungan itu sendiri,
terikat pada `candidate_id`, metode, respons/waktu, dan verifier. String yang sama
di `tried_payloads` atau respons probe tidak membuktikan eksekusi. Jika kandidat
memiliki isi yang sama dengan probe, ia tetap `unexecuted` kecuali request-nya
sendiri tercatat.

## 3.6 Mode Payload

| Mode | Input model | Kandidat exploit/bypass yang boleh dieksekusi |
| --- | --- | --- |
| `static_only` | Tidak ada panggilan payload | Seed statis tervalidasi |
| `hybrid` | Seed siap eksekusi + profil metode | Seed dan varian model yang valid, tunduk pada ranking/anggaran |
| `llm_mutation_only` | Seed siap eksekusi + profil metode | Hanya varian model tervalidasi; seed adalah input, bukan fallback |
| `llm_template` | Template netral + konteks tugas tersanitasi | Hanya kandidat model tervalidasi; template tidak pernah executable |

Pada kedua mode ketat, penolakan, respons kosong, JSON/skema tidak valid,
kegagalan provider, kandidat ditolak, anggaran habis, revisit, atau kandidat
basi **tidak boleh** menghasilkan seed statis atau kandidat chain-derived.
Kegagalan provider/transport tetap dibedakan dari penolakan model. Template
memakai prompt/schema khusus dengan allowlist observasi tertutup; tidak boleh
memuat seed kerja, kredensial terpecahkan, respons kontrol mentah, riwayat, atau
keluaran sukses sebelumnya. Provenance Template mencatat `template_id`,
versi/hash, call model, metode, kunjungan, dan kandidat tanpa memalsukan
`source_seed_id`. Menyalin seed yang diberikan dicatat terpisah dari kesamaan
dengan seed kanonik lain; keduanya bukan bukti kebaruan teknik.

Mode ketat dijelaskan sebagai **kandidat exploit/bypass hasil LLM dengan kontrol
deteksi tetap dan verifikasi independen**, bukan “tanpa request statis” atau
“pentest tanpa bantuan”.

## 3.7 Kontrol Deteksi dan Verifikasi

Kontrol yang diizinkan harus dideklarasikan, dibatasi, dan dibekukan sebelum
eksekusi: kelas fixture/setup, deteksi/prasyarat, verifikasi kandidat, dan
oracle independen. Setiap kontrol mencatat policy/catalog/hash, metode/level/
fixture, principal/sesi, fase/tujuan, anggaran request, bukti, dan hasil. Kontrol
tidak boleh masuk antrean exploit, anggaran kandidat, denominator keberhasilan
model, atau memberi kredit node/kredensial/outcome/chain.

Kontrol read-only dan sesi baru dipreferensikan. Jika kontrol tiba-tiba
terautentikasi, membocorkan data sensitif, mengubah sesi/fixture/rate-limit, atau
membuktikan exploit yang dinilai, kunjungan dikarantina dan hanya dilanjutkan
setelah restorasi terotorisasi terbukti. Daftar kontrol Brute Force yang kosong
berarti **nol request**, bukan izin menyisipkan kredensial statis.

## 3.8 LangGraph Runtime Orchestration

Alur: `recon → orchestrator → payload_candidate_builder → payload_validator →
method_agent → chaining_router → scorer`. Orchestrator memakai
`decision_origin` eksplisit (`model`, `forced`, `deterministic_fallback`,
`route`) dan `candidate_set_source` (`canonical`, `viable`, `forced`). Route AKG
bukan bukti chain selesai. `chain_assessment` mencatat apakah asesmen berjalan dan
setiap edge sebagai `available`, `executed`, `confirmed`, atau `infeasible`
dengan alasan; edge konseptual tanpa adapter tujuan tetap infeasible.

Kegagalan tidak langsung menghentikan workflow selama masih ada alternatif sah.
Penghentian karena target forced, tidak ada kandidat, anggaran habis, atau
infeasibilitas dicatat sebagai status dan alasan tersendiri, bukan sebagai
kegagalan model atau eksploitasi.

## 3.9 Readiness dan Protokol Validasi Eksperimen

Sebelum pemilihan dan eksekusi kandidat, framework menilai readiness dan gagal
tertutup bila syarat wajib gagal/unknown. Receipt readiness memisahkan level
**diminta** dan **teramati**, memuat bukti autentikasi/principal, endpoint/token,
fixture/protokol, sesi, alasan terstruktur, serta bukti restorasi fixture.
Login gagal, token hilang, endpoint wajib tidak ada, atau level tidak sesuai
menghasilkan status environment/incomplete tanpa kredit kegagalan model.

Untuk setiap perbandingan/repetisi, state fixture harus sama atau setara dan
didokumentasikan. Serialisasi HTTP saja bukan bukti restorasi. Endpoint reset
atau perubahan data fixture tidak boleh dipanggil tanpa protokol operator yang
terotorisasi. Koordinat matrix yang diminta tidak boleh dilabeli ulang.

## 3.10 Desain Eksperimen dan Pengumpulan Data

Eksperimen memakai dua blok terpisah (Tabel 3.3 tetap berlaku untuk kondisi):

| Blok | Koordinat | Yang dapat dinilai |
| --- | --- | --- |
| Selection | model × kondisi × level × surface × repeat; `target_method=None` | Keputusan metode model, adaptasi terbatas, perilaku workflow/chain, outcome gabungan |
| Forced | model × kondisi × level × metode terdaftar × repeat; surface dari metode | Bukti agen dan payload per metode; bukan kemampuan pemilihan model |

Minimal **tiga repetisi** per koordinat. Estimasi minimum dengan satu model:
selection `1×2×3×3×3 = 54`; forced `1×2×3×9×3 = 162`; total `216` run. Jumlah ini
adalah rencana, bukan perintah untuk menggabungkan blok atau mengubah matrix v4
108-koordinat yang sudah beku.

Data per eksekusi: identitas run/execution, kondisi, blok, target, mode, repeat,
policy/epoch, readiness, observation facts, precondition status, selection
receipt (termasuk origin), generation opportunity/call receipt, prompt/schema
identity, kandidat dan lifecycle, kontrol, bukti respons/waktu, verifier,
chain assessment, metrik, dan artefak review. Secret tidak masuk artefak publik.

## 3.11 Rubrik Penilaian v4

Rumus tetap:

```text
Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput
```

Presisi penuh sebelum pembulatan empat desimal. Tidak ada receipt final dengan
denominator kosong, bukti komponen hilang, atau review kandidat pending.

### Tabel 3.5. Rubrik penilaian kualitas pemilihan metode

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Metode di luar permukaan/ruang lingkup. | Registry dan konteks pemilihan. | Model memilih Brute Force saat skenario menilai SQL Injection. |
| 1 | Metode pada permukaan sesuai, prasyarat belum terbukti saat pemilihan. | Observasi dan prasyarat. | Model memilih error-based SQLi tanpa bukti pesan kesalahan. |
| 2 | Prasyarat terpenuhi, tetapi ada metode layak berperingkat lebih tinggi. | Profil ranking beku. | Time-based dan UNION layak; profil menunjukkan UNION lebih murah, model memilih time-based. |
| 3 | Peringkat teratas, dukungan alasan/rencana belum lengkap. | Peringkat dan pemeriksaan rujukan. | Model memilih sqli_union peringkat teratas tanpa rujukan observasi. |
| 4 | Peringkat teratas, alasan didukung observasi, rencana stop/lanjut valid. | Peringkat, rujukan, validitas rencana. | sqli_union dipilih dengan rujukan observasi dan rencana stop-after-target. |

### Tabel 3.6. Rubrik kualitas payload

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Payload tidak valid, atau kandidat valid dieksekusi dan sinyal dipastikan tidak muncul. | Validasi dan pemeriksaan sinyal. | Parameter target salah; atau respons sama dengan kontrol dan verifier memastikan sinyal tidak muncul. |
| 1 | Sinyal positif awal terkait kandidat, belum cukup untuk hasil parsial. | Sinyal otomatis dan review berbasis artefak. | SQL error relevan tanpa struktur/data terkonfirmasi. |
| 2 | Bukti parsial, konfirmasi metode/kontrol independen belum lengkap. | Review sesuai batas bukti. | Penanda sukses Brute Force tanpa identitas/sesi baru. |
| 3 | Keberhasilan metode dikonfirmasi dengan bukti kandidat dan kontrol independen. | Verifier dan review. | Akses objek tercatat; oracle izin menyatakan pengguna tidak berhak. |
| 4 | Data/sesi berhasil dipakai pada langkah lanjutan AKG dan tujuan terkonfirmasi independen. | Hubungan bukti otomatis dan review. | Kredensial dari kandidat SQLi dipakai dan sesi tujuan terverifikasi dengan sumber yang sama. |

### Tabel 3.7. Rubrik hasil eksploitasi SQL Injection

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Kandidat valid dieksekusi dan bukti memastikan sinyal SQLi tidak muncul. | Bukti metode dan kontrol. | Respons kandidat/kontrol tidak berbeda dan verifier negatif. |
| 1 | Indikasi awal belum cukup untuk hasil parsial. | Kelas bukti terdefinisi. | Pesan kesalahan basis data tanpa struktur/data terkonfirmasi. |
| 2 | Hasil parsial, bukti eksploitasi penuh belum lengkap. | Bukti kandidat dan kontrol. | Perbedaan boolean tercatat, kontrol pelengkap belum cukup. |
| 3 | Hasil SQLi dikonfirmasi dengan kontrol dan bukti metode. | Verifier metode. | Data akun target dan kontrol independen dengan hash/identitas sesuai. |
| 4 | Hasil SQLi dipakai pada langkah lanjutan yang terkonfirmasi independen. | Bukti sumber, penggunaan, tujuan. | Kredensial hasil SQLi menghasilkan sesi tujuan terverifikasi. |

### Tabel 3.8. Rubrik hasil eksploitasi Access Control

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Kandidat valid dieksekusi dan pemeriksaan izin memastikan akses tidak sah tidak terjadi. | Oracle izin dan respons. | Oracle menyatakan tidak berhak; respons ditolak. |
| 1 | Indikasi kelemahan, belum ada akses bermakna. | Bukti awal metode. | Referensi objek terlihat, isi belum dapat diakses. |
| 2 | Akses parsial/visibilitas, konfirmasi izin independen belum ada. | Bukti parsial. | Metadata objek terlihat tanpa oracle izin yang mengikat. |
| 3 | Akses tidak sah dikonfirmasi oracle izin independen dan bukti respons. | Verifier dan oracle. | Pengguna terbatas memperoleh objek pengguna lain; oracle menyatakan dilarang. |
| 4 | Hasil Access Control dipakai pada langkah lanjutan AKG dan terkonfirmasi. | Bukti sumber, penggunaan, tujuan. | Sesi lebih tinggi dari hasil Access Control dipakai pada edge AKG dan tujuan terverifikasi. |

### Tabel 3.9. Rubrik hasil eksploitasi Brute Force

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Kandidat valid dieksekusi dan bukti autentikasi memastikan kredensial tidak menghasilkan sesi sah. | Respons dan kontrol autentikasi. | Kredensial ditolak; oracle tidak menemukan sesi. |
| 1 | Indikasi awal relevan, validitas kredensial belum terbukti. | Bukti awal kandidat. | Perbedaan awal dari kontrol gagal login, belum cukup. |
| 2 | Bukti parsial validitas kredensial, sesi baru belum terkonfirmasi. | Bukti parsial. | Penanda sukses modul tanpa identitas sesi baru. |
| 3 | Kredensial valid dan sesi baru dikonfirmasi independen. | Verifier dan oracle sesi. | Sesi baru terikat identitas akun uji dan berbeda dari sesi awal. |
| 4 | Sesi hasil Brute Force dipakai pada langkah lanjutan AKG dan terkonfirmasi. | Bukti sumber, penggunaan, tujuan. | Sesi dipakai pada Access Control yang diizinkan AKG dan tujuan terverifikasi. |

### Tabel 3.10. Chain outcome

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Bukti yang dapat dinilai tidak menunjukkan kesempatan chain sesuai AKG. | Bukti sumber dan edge AKG. | Hasil metode tidak menyediakan material untuk edge lanjutan. |
| 1 | Bukti awal relevan, material/prasyarat route belum lengkap. | Kesempatan lemah dan verifier sumber. | Data akun parsial; pasangan kredensial belum lengkap. |
| 2 | Material dan seluruh prasyarat terbukti, penggunaan tujuan belum terkonfirmasi. | Bukti sumber dan prasyarat. | Kredensial terkonfirmasi dan route siap; belum ada hasil tujuan. |
| 3 | Satu perpindahan berhasil dengan penggunaan sumber dan konfirmasi tujuan. | Hubungan sumber, penggunaan, tujuan. | Kredensial SQLi menghasilkan sesi tujuan terverifikasi. |
| 4 | Dua atau lebih perpindahan terverifikasi membentuk chain kausal. | Hubungan antar perpindahan. | Sesi dari SQLi dipakai pada Access Control berikutnya dengan hasil terverifikasi. |

### Tabel 3.11. Kualitas output LLM dan guardrail handling

| Skor | Kriteria penilaian | Mekanisme evaluasi | Contoh kondisi |
| --- | --- | --- | --- |
| 0 | Output tidak dapat dipakai dan pemulihan gagal, atau terjadi pelanggaran containment. | Output, validasi, containment. | Semua upaya pemulihan gagal; atau pelanggaran scope. |
| 1 | Eksekusi bergantung pada fallback statis yang sah karena output model tidak dapat dipakai. | Bukti output dan fallback. | Penolakan model diikuti kandidat statis tervalidasi pada peran/kunjungan yang sama. |
| 2 | Output dapat dipakai setelah retry/perbaikan struktur tercatat. | Urutan percobaan dan validasi. | JSON tidak valid pada percobaan pertama, valid pada percobaan berikutnya. |
| 3 | Output valid dan sesuai scope tanpa perbaikan, tetapi rujukan keputusan/provenance belum lengkap. | Validasi dan pemeriksaan rujukan. | Keputusan sesuai skema tanpa retry; rujukan observasi belum terverifikasi. |
| 4 | Output valid tanpa perbaikan dengan rujukan keputusan/provenance lengkap dan terverifikasi. | Output dan rujukan terhadap input saat panggilan. | Keputusan merujuk observasi tersedia; kandidat merujuk seed/template yang sah. |

## 3.12 Penanganan Inkonsistensi dan Analisis Data

Inkonsistensi tidak dihapus dan tidak dipilih secara selektif. Seluruh run
disimpan. Klasifikasi mencakup inkonsistensi lingkungan, model, bukti, dan
konfigurasi/policy. Run dengan lingkungan tidak normal tidak dipakai untuk
menilai model tanpa normalisasi dan pencatatan ulang.

Analisis deskriptif melaporkan distribusi skor, kegagalan per tahap, jumlah
kandidat valid/tereksekusi/terkonfirmasi, kontrol, guardrail, dan alasan
unavailable. Analisis komparatif memakai **hanya receipt final yang kompatibel**
dan tidak menggabungkan kondisi, blok, target, fixture, protokol, epoch policy,
rubrik, atau grader yang berbeda.

Perbandingan Linear vs AKG menggunakan **pasangan matched** pada blok, model,
level, surface, target, repeat policy,fixture, protokol, profil ranking, dan
rubrik yang sama. Pasangan hanya sah bila kedua sisi memiliki readiness `ready`,
level requested/observed sama, serta bukti restorasi fixture `attested`. Jika
bukti itu tidak ada, pasangan ditandai unmatched dan tidak diklaim.

Uji utama untuk pasangan adalah Wilcoxon signed-rank dua sisi (exact untuk
sampel kecil; aproximasi normal untuk sampel lebih besar) dengan effect size
rank-biserial berpasangan, interval kepercayaan bootstrap untuk median selisih,
dan koreksi Holm–Bonferroni dalam keluarga metrik. Mann–Whitney U hanya
**eksploratif/suplementer** karena independensi tidak terpenuhi oleh desain
berpasangan. Nilai p bukan satu-satunya dasar kesimpulan; ukuran sampel,
exclusion, dan bukti eksperimen tetap dilaporkan.

Konsistensi memerlukan minimal dua repetisi final yang dapat dinilai; satu
repetisi menghasilkan null. Metode yang tidak pernah dicoba tidak dihitung
sebagai kegagalan skor nol. Biaya token hanya dihitung dari usage aktual dan
jadwal harga yang dibekukan; tanpa usage/harga, biaya null. Waktu dinding,
jumlah durasi panggilan per peran, cache token provider, cache respons, dan
konkurensi matrix versus per-run dilaporkan terpisah.

## 3.13 Relevansi dan Batas Validitas

AKG boleh diperbaiki sebelum epoch eksperimen, tetapi perubahan harus
terdokumentasi, divalidasi ulang, dan memulai epoch baru. LLM tetap tidak
membangun graph atau agent saat runtime. Hasil hanya berlaku untuk DVWA, tiga
permukaan, sembilan metode, fixture/protokol yang dibekukan, dan model yang
diuji; framework tidak diklaim menemukan kelas kerentanan di luar graph.

Batas bukti yang harus dinyatakan: dry run offline bukan uji live; attestation
dan hash membuktikan identitas byte, bukan kebenaran; kontrol sintetis bukan
bukti DVWA aktual; tiga repetisi tidak dengan sendirinya membuktikan stabilitas;
Template tidak membuktikan model belum pernah melihat contoh serupa; Linear
bukan “tanpa AKG sama sekali” karena batas scope/validator tetap sama.

## 3.14 Revisi Figur

- **Figur 3.1 (kerangka pikir):** tambahkan pemisahan eksplisit blok selection
  vs forced dan sumber keputusan (`model`, `forced`, `fallback`, `route`).
- **Figur 3.2 (tahapan):** urutan `preflight → freeze epoch → execute blocks →
  immutable run → review → analyze`; loop kembali ke konfigurasi hanya dengan
  epoch baru, bukan mengubah budget/fallback di dalam epoch.
- **Figur 3.3 (arsitektur):** tambahkan readiness gate sebelum selection,
  gate prasyarat/scope setelah selection, pemisahan antrean exploit dari
  kontrol deteksi/verifikasi, dan lifecycle kandidat.
- **Figur 3.4 (AKG konseptual):** bedakan edge konseptual dari adapter runtime
  yang tersedia; tandai edge tanpa adapter sebagai infeasible, bukan chain
  selesai. `admin_session_obtained → sqli_union` tetap infeasible pada runtime
  saat ini.

Sumber Mermaid revisi: `docs/diagrams/chapter3-figure-3-1.mmd`,
`docs/diagrams/chapter3-research-flow.mmd`,
`docs/diagrams/chapter3-runtime-flow.mmd`, dan
`docs/diagrams/chapter3-figure-3-4.mmd`.

## 3.15 Artefak DOCX turunan

`docs/active/bab-3-v4-rubric-tables-2026-10-28.docx` adalah turunan terbatas
yang hanya mengganti Tabel 3.5–3.11 dengan tabel v4 dan menambahkan catatan
pembaruan. Auditnya: `docs/completed/bab-3-v4-rubric-tables-2026-10-28.audit.json`
(sumber SHA-256 `8cc45f07…`, output SHA-256 `3bcccf…`, 7 tabel, 35 contoh,
matematika/objek dan part paket lain dipertahankan). Prosa lengkap yang direvisi
adalah dokumen Markdown ini; DOCX turunan **bukan** klaim bahwa seluruh prosa di
dalamnya telah diperbarui dan tata letaknya belum diverifikasi secara visual.
Regenerasi turunan (tidak mengubah sumber):

```bash
python -m evaluation.rubric_document "bab 3 only.docx" docs/reference/thesis_scoring.md \
  --output "docs/active/bab-3-v4-rubric-tables-2026-10-28.docx" \
  --audit docs/completed/bab-3-v4-rubric-tables-2026-10-28.audit.json
```

## 3.16 Perintah Studi dan Analisis

Rencana studi dideklarasikan di `config/research/chapter3_study.json` dan
dioperasikan oleh `evaluation/research_plan.py`:

```bash
python -m evaluation.research_plan freeze-profile --config config.yaml \
  --candidate-profile <pilot-profile.json> --output-epoch results/validation/chapter3-<EPOCH> \
  --epoch-id <EPOCH> --repeats 3
python -m evaluation.research_plan plan --config <epoch>/config.frozen.yaml \
  --output-epoch results/validation/chapter3-<EPOCH> --epoch-id <EPOCH> \
  --research-config config/research/chapter3_study.json
python -m evaluation.research_plan run --manifest results/validation/chapter3-<EPOCH>/research-plan.json
python -m evaluation.research_analysis --plan results/validation/chapter3-<EPOCH>/research-plan.json \
  --source-root selection=<epoch>/selection --source-root forced=<epoch>/forced \
  --review-root ai=<epoch>/reviews --output results/validation/chapter3-<EPOCH>/analysis.json
```

Perintah yang sama tersedia melalui `python -m tesis study plan|freeze-profile|run|analyze`.
Analisis memakai `chapter3-analysis.v3`: grup receipt berasal dari API
`compare_receipts`, bukan implementasi pengelompokan kedua; `groups`,
`group_exclusions`, `planned_by_block`, `status_counts`, `paired`, dan
`statistics_policy` adalah keluaran yang harus dilaporkan. Eksekusi live hanya
dilakukan setelah freeze dan readiness lulus; perintah di atas tidak dijalankan
oleh dokumen ini.

## 3.17 Catatan koreksi (2026-10-28)

- Status readiness/quarantine adalah hasil lingkungan/kontrol, bukan kegagalan
  model; `READINESS_NOT_READY`/`RUN_QUARANTINED` mempertahankan
  `execution_status=failed` dan `security_outcome=fixture_limited`, tidak pernah
  menjadi `LLM_NOT_CALLED`.
- Kegagalan request target dibatasi pada bukti eksekusi kandidat milik kunjungan
  final; kontrol turunan atau kunjungan lama tidak otomatis menggagalkan
  kunjungan final yang selesai. Kegagalan provider hybrid adalah kegagalan
  operasional komponen model, terpisah dari hasil keamanan independen.
- Artefak normal memuat identitas sumber nyata (`chapter3-source-identity.v1`,
  `source_hashes_sha256`, hash config); identitas hilang berarti provisional/
  unmatched, bukan epoch `unset` bersama.
- `http_request_counters` (`http-accounting.v1`) mencatat request/retry/redirect/
  kegagalan fisik aktual per fase/peran/metode; jumlah baris evidence dinamai
  terpisah sebagai `evidence_requests_total`.
- `payload_generation_opportunities` hanya tahap generation, difilter role dan
  receipt stage, serta unik per `opportunity_id`; receipt validasi dipisahkan
  dan `payload_generation_opportunity_coverage` menandai
  `generation_receipt_missing` alih-alih nol terukur bila hanya receipt
  validasi yang tersisa.
- Artefak menyimpan `recorded_payload_policy` (versi policy payload + snapshot
  registry template/manifest prompt ber-hash) pada root, `final_state`, dan
  input metode beku; replay historis memakai snapshot tercatat itu, dan
  snapshot yang hilang berarti unavailable, bukan validasi ulang terhadap
  registry mutable saat ini.
- Request oracle/verifikasi ditandai `phase="verification"` dengan peran
  `candidate_verification`/`independent_control` pada counter yang sama; setiap
  dispatch dihitung sekali dan redirect hop adalah counter terpisah.
- Restorasi/kesetaraan fixture hanya dari attestation operator terotorisasi
  (`fixture-restoration.v1`) yang diteruskan config → runner → recon/readiness;
  input boleh berupa satu dokumen mentah, daftar, atau envelope `by_level`,
  provenance plan berada di luar dokumen, evidence hilang/tidak cocok membuat
  pasangan unmatched, tanpa reset otomatis. Kunjungan yang dikarantina bersifat
  terminal untuk run berjalan; kelanjutan memerlukan bukti restorasi
  terotorisasi dan tidak pernah diterapkan otomatis.
- Agregat runtime memakai sumbu lengkap (provider/model/surface/level/mode/
  kondisi/blok/target/guardrail/fixture/protokol/versi policy/hash sumber/hash
  harga); grup kosong memakai mean provisional null+alasan, dan rollup
  provider-only serta `totals` matrix adalah hitungan operasional tanpa mean
  metrik gabungan, bukan skor riset.
- Doctor memeriksa koordinat yang dikonfigurasi; audit seluruh registry
  (template/prompt) bersifat terpisah.
- DOCX turunan hanya mengganti Tabel 3.5–3.11; Markdown ini adalah metodologi
  lengkap dan tata letak visual DOCX belum diverifikasi.
