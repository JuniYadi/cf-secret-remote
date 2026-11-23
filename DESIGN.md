# cf-secret-remote — Desain v1

Vault untuk kredensial QA dan secret, untuk tim atau satu orang. Targetnya tim teknis kecil—developer, QA, agensi, dan startup—yang punya akun Cloudflare. Hanya berjalan di Cloudflare Workers + D1 dalam akun pengguna; SaaS hosted di luar cakupan.

Server tidak bisa membaca nilai (ADR 2), akses dapat dibuktikan lewat audit (ADR 6), dan mesin serta agent mendapat kredensial lewat AppRole (ADR 15 dan 17). Login item dan alur CLI, web, ekstensi, serta import masih direncanakan (ADR 29–33).

Ini bukan password manager konsumen umum: v1 tidak punya kartu, identitas, passkey, atau lampiran file; catatan aman disimpan sebagai Secrets. Di v1, kredensial diberikan ke test runner, bukan LLM. Jangan berikan password mentah ke agent; untuk HTTP key gunakan agent-safe proxy (ADR 17; lihat juga ADR 35).

## Platform
- Worker + SPA: TypeScript, Hono. D1 untuk data. Migrasi lewat wrangler.
- CLI: Bun, `bun build --compile` jadi satu binary, dibagikan lewat GitHub Releases.
- Monorepo: `worker/`, `cli/`.

## Auth
- Manusia: Cloudflare Access hanya melindungi UI dan `/cli/login`. `cfs login` pakai loopback, hasilnya token `cfs` berumur pendek.
- Mesin/agent: AppRole yang dikelola sistem sendiri (bukan Access Service Token, karena itu hanya bisa dikelola admin Cloudflare).
  - Kredensial: `role_id`, `secret_id` (di D1 hanya hash; TTL, batas pemakaian, CIDR opsional), dan private key (tidak pernah ke server).
  - Login: `POST /v1/auth/approle/login`, dengan rate limit.
- `/v1/*` di luar Access, dijaga token `cfs`.
- Admin awal: env var `BOOTSTRAP_ADMIN_EMAIL`.

## Otorisasi (ala Vault)
- Policy: path glob + capability (`create`, `read`, `update`, `delete`, `list`). Default deny.
- Role: mengikat identitas (email/domain/AppRole) ke policy.
- Tanpa namespace dan `sudo` di v1.

## Enkripsi (E2E, tanpa master key)
- Tiap versi secret punya DEK acak (AES-GCM). DEK dibungkus ke kunci keyring (ECDH + AES-GCM, WebCrypto).
- Satu keyring per prefix level atas. Anggota menerima private key keyring yang dibungkus ke public key mereka.
- Private key manusia dibungkus passphrase (PBKDF2/Argon2), blob disimpan di D1. Server tidak bisa membukanya.
- Private key AppRole dipegang mesin, tidak pernah dikirim ke server.
- Server hanya menyimpan ciphertext dan kunci terbungkus. Path dan nama key plaintext, nilai terenkripsi.
- Cabut akses: keluarkan dari keyring, putar kunci keyring, tulis ulang secret (`cfs keyring rotate`).
- Dua gerbang: policy di server (boleh ambil ciphertext) dan kunci kriptografis (bisa dekripsi).

## Data
- Satu path = satu bundle key-value (`myapp/dev`). Environment = bagian dari path.
- Tiap update membuat versi baru. Tanpa rollback di v1.

## Audit
- Tabel D1 append-only, retensi 90 hari.
- Event: read, write, delete, list, login, denied, perubahan policy/role/AppRole.
- Field: pelaku + tipe (`human`, `approle`, `agent`), `--purpose`, path, versi, IP, user-agent, waktu.
- Yang tercatat adalah pengambilan ciphertext, bukan dekripsi. Nilai secret tidak pernah dicatat.

## CLI
`cfs run <path> -- <cmd>`, `get`, `set`, `list`, `login`, `audit`, `role`, `policy`, `approle`, `keyring`.

## UI
- SPA (CSR) lewat static assets Workers. Dekripsi di browser, private key hanya di memori (non-extractable CryptoKey), kunci otomatis saat idle.
- Reveal per key, CSP ketat, hash build dipublikasikan.
- Prototipe pertama: Claude Artifact.

## Ditunda
MCP, dynamic secret, rollback versi, namespace, passkey/WebAuthn PRF.

## Batas yang harus diingat
- Lupa passphrase = kunci hilang. Pemulihan lewat admin yang membungkus ulang.
- Audit tidak melihat dekripsi.
- Pembaca yang sudah mendapat nilai tidak bisa dicabut ke belakang.
- UI web masih bergantung pada JS yang disajikan server.

---

# Addendum: diferensiasi dan keputusan produk (disetujui)

## Posisi
"Vault tanpa ops, untuk manusia dan agent AI. Server tidak bisa membaca secret, setiap akses bisa dibuktikan, dan agent tidak pernah melihat key yang mereka pakai."
- Target v1: tim kecil (sampai ~50 orang, batas gratis Cloudflare Access) dan pembuat agent AI. Bukan pengganti cluster Vault enterprise.
- Koreksi: Vault OSS punya audit device (file/syslog) tapi tanpa UI atau pencarian, dan server selalu bisa mendekripsi saat unsealed. Pembeda kita: zero-ops (tanpa unseal/cluster), E2E, audit yang bisa dibaca.

## Tiga pembeda utama v1
1. **Agent-safe mode dengan budget.** `cfs proxy` berjalan lokal di mesin agent, mendekripsi lokal, dan menyuntikkan key ke request keluar. Agent hanya melihat respons. Allowlist host ada di policy, jadi agent yang kena prompt injection tidak bisa mengirim key ke domain penyerang. Budget per agent: maks baca per jam, wajib isi tujuan, persetujuan manusia untuk `*/prod`.
2. **Access request dengan persetujuan (JIT).** Minta akses prod, approver menyetujui (webhook Slack dulu, email kedua), akses kedaluwarsa otomatis. Dua bagian: server memberi policy berbatas waktu, approver dengan vault terbuka membungkus kunci grup untuk peminta. Approver harus online. Opsional putar kunci grup setelah akses berakhir.
3. **Audit tamper-evident dengan alert.**
   - Tiap baris audit menyimpan hash baris sebelumnya, hash kepala rantai dikirim setiap hari ke webhook Slack dan email admin (salinan di luar sistem), `cfs audit verify` memeriksa rantainya.
   - Alert default (webhook kompatibel Slack): event `blocked`, agent membaca path `*/prod`, login pertama dari IP/jaringan baru, lonjakan baca (>20 dalam 5 menit).

## Keputusan pendukung
- **Strict E2E saja di v1.** Tidak ada "trusted mode". Konsekuensi: tanpa rotasi sisi server, dynamic secret, atau proxy hosted. Bisa ditambah nanti jika diminta.
- **Free tier D1 (~100k write/hari).** Tulis audit di-batch, ada batas baca per agent, meter "pemakaian free tier" di layar Activity dengan peringatan di 80%.
- **Distribusi:** open source (Worker dan CLI). `cfs deploy` menyiapkan D1, Worker, dan policy Access di akun Cloudflare pengguna. Kami tidak meng-host data.
- **Batas yang dinyatakan terbuka di docs:** tanpa dynamic database credentials, PKI, atau transit encryption. Catatan "pakai Vault jika butuh ini".

## Ditunda setelah v1
Sync (`cfs sync` ke Workers, GitHub Actions, Vercel), `cfs diff` terhadap `.env.example`, one-time share, pengingat rotasi dan laporan kedaluwarsa.

## Istilah di UI (untuk orang awam) vs istilah teknis
| UI | Teknis |
|---|---|
| Groups | keyring |
| Permissions | policy + role |
| Apps & bots (access kit) | AppRole |
| Activity | audit log |
| Vault password | passphrase |
| Show | reveal |
UI default English dengan tombol EN/ID. Detail teknis ada di bagian "Technical details" yang tertutup.

## Layar UI
Sudah ada di kanvas (13 layar): Sign in, Create vault password, Unlock, Secrets, Secret detail, Edit (tab Fields), Edit (tab JSON), Import .env (add file), Import .env (review and save), Groups, Permissions, Apps and bots, Activity.
Akan ditambah: Access requests dan approval, Agent policy (allowlist host, budget, wajib tujuan), Alerts. Layar Activity perlu meter free tier dan status rantai hash.

---

# Addendum: CLI, host, dan layar app/bot (disetujui)

## Login CLI
- `cfs login --host URL` membuka browser ke `/cli/login` (di belakang Access). Halaman "Authorize cfs?" menampilkan nama perangkat, kode pendek yang harus sama dengan di terminal, dan masa berlaku. Sesudahnya halaman "You're signed in".
- Layar "Signed-in devices": perangkat, terakhir dipakai, tombol Sign out (cabut sesi).
- `cfs unlock` meminta vault password sekali, menyimpan kunci terbuka di keychain OS dengan TTL (default 1 jam, `--ttl`). `cfs run` meminta password hanya jika terkunci. Mesin dan agent memakai access kit, bukan alur ini.

## Penentuan host (prioritas tertinggi ke terendah)
1. flag `--host https://vault.myorg.com`
2. env `CFS_HOST`
3. file proyek `.cfs.json`
4. profil di `~/.config/cfs/config.json` (hasil `cfs login --host ...`, banyak profil, `--profile`)
Hanya `https://`. Host baru dipakai pertama kali: CLI bertanya "Sign in to <host>? (y/N)", lalu disimpan sebagai tepercaya, agar `.cfs.json` dari repo asing tidak mengarahkan login ke server lain.
`cfs deploy --domain vault.myorg.com` memasang custom domain di Worker dan aplikasi Access pada hostname yang sama (domain harus ada di akun Cloudflare pengguna), lalu menulis host ke `.cfs.json`. Tanpa `--domain`, memakai `*.workers.dev`.

## File proyek `.cfs.json` (di-commit, tanpa nilai rahasia)
Bentuk minimal:
```json
{ "host": "https://vault.myorg.com", "project": "myapp" }
```
`cfs run -- cmd` memuat `myapp/dev`, `--env staging` memuat `myapp/staging`.
Bentuk eksplisit untuk secret bersama:
```json
{ "host": "https://vault.myorg.com", "default": "dev",
  "envs": { "dev": ["shared/common", "myapp/dev"], "staging": ["shared/common", "myapp/staging"], "prod": ["myapp/prod"] } }
```
Entri belakang menimpa entri depan. Jika satu secret tidak bisa dibuka, perintah gagal dan menyebut mana (tidak memuat separuh).
Urutan: (1) argumen eksplisit `cfs run myapp/dev -- cmd` mengabaikan file, (2) `.cfs.json` terdekat, dicari naik ke direktori induk seperti git, (3) tanpa file: gagal dengan petunjuk `cfs ls` dan `cfs init`.
`cfs init` menulis file ini secara interaktif.
`--env prod` meminta konfirmasi "Load production secrets? y/N" dan, bila policy mewajibkan, memicu access request.

## Layar tambahan
Apps & bots dipecah: daftar, form "New app or bot", "Kit ready" (sekali tampil), detail app. Login CLI: Authorize cfs, You're signed in, Signed-in devices.

## Repo dan deployment
**Disetujui:** web (SPA) disajikan oleh Worker lewat static assets, bukan R2. Satu hostname, satu aplikasi Cloudflare Access, tanpa CORS. `not_found_handling = "single-page-application"` untuk routing SPA, dan `run_worker_first` untuk `/api/*`. Web dan API dirilis sebagai satu unit, jadi tidak ada ketidakcocokan versi. Alasan menolak R2: butuh langganan R2 (metode pembayaran), tidak punya routing SPA, rilis terpisah dari API, header keamanan harus diatur terpisah, dan `cfs deploy` bertambah langkah.

**Disetujui juga:**
- Monorepo dengan Bun workspaces (tanpa Turborepo atau Nx): `apps/api`, `apps/web`, `apps/cli`, `packages/core`. Kerangka sudah dibuat, belum ada logika.
- `packages/core` memegang kripto (hanya WebCrypto), format kit, skema, dan kode sidik jari, dipakai browser, CLI, dan Worker. Tes memakai vektor uji bersama lintas browser dan CLI.
- Rilis berisi binary CLI dan satu bundel Worker (kode, web hasil build, migrasi D1) yang dipasang `cfs deploy`.
- Urutan kerja: `core`, `api`, `cli`, lalu `web`.
- R2 opsional (hanya backup otomatis). Titik periksa audit dikirim ke Slack atau email, bukan R2.

## Fitur tambahan (disetujui)
1. **Offboarding satu klik** (Groups > Offboard a teammate): keluarkan dari semua grup, kunci ulang secret di grup itu, akhiri sesi CLI, cabut peran, pindahkan app yang dimiliki, lalu tampilkan daftar nilai yang pernah dibukanya dalam 90 hari (dari Access history) untuk diganti di sumbernya. Mengingatkan bahwa penghapusan dari login perusahaan dilakukan di penyedia login.
2. **Aturan minimal dua admin** (Settings > Admins): peringatan jika hanya satu admin yang memiliki kunci. Menampilkan status kunci vault dan kunci pemulihan tiap kandidat. Peringatan juga tampil di Groups.
3. **Backup dan restore terenkripsi** (Settings > Backup, Restore): cadangan harian ke penyimpanan Cloudflare milik pengguna, hanya berisi data terkunci. Restore memeriksa berkas, menampilkan isi, dan menjelaskan apa yang hilang sejak cadangan.
4. **Versi secret** (tab Versions): daftar versi, perbandingan tingkat nama key (ditambah, diubah, dihapus, tanpa menampilkan nilai), dan pulihkan versi lama sebagai versi baru. Peringatan bahwa memulihkan nilai lama bisa mengembalikan nilai yang bocor.
5. **Settings dan status deployment**: versi Worker, kesehatan database, status Access, alamat, pemakaian free tier, retensi log, notifikasi. Menu Settings ada di sidebar semua layar.
6. **Perilaku saat kuota habis**: membuka secret, login, dan membaca tetap jalan. Menyimpan secret baru dan mengubah grup dijeda sampai reset 00:00 UTC. Pembukaan ditahan lalu dicatat saat ruang tersedia. Layar menunjukkan siapa yang paling banyak memakai dan cara menghindarinya.
Belum dikerjakan: pemilik dan tanggal "ganti sebelum" per secret; SDK dan GitHub Action resmi (setelah v1).

## Merek: logo "Bold key"
- Logo aplikasi: kunci yang badan dan giginya berupa titik "•••" (varian V1, dipilih). Cincin tebal, dua titik besar, satu gigi. Ide: titik tersamar adalah yang terlihat di seluruh UI saat nilai disembunyikan.
- Favicon: varian V3 (kepala kunci berupa cakram penuh dengan lubang), karena paling kuat di 16px.
- Warna: teal `#0B7A75` dengan gambar putih. Tulisan "cfs" memakai Space Grotesk Bold.
- Berkas ada di `design/brand/`: `cfs-mark.svg` (aplikasi), `cfs-favicon.svg`, `cfs-mark-mono.svg` (satu warna, `currentColor`). Ini sketsa pilihan arah; gambar ulang di atas grid sebelum rilis.
- Ikon gembok tetap dipakai hanya untuk arti "terkunci" (nilai terkunci, vault terkunci), bukan sebagai logo.

## Aturan judul dan breadcrumb di UI
1. Halaman bagian utama (Secrets, Groups, Permissions, Apps & bots, Activity) berjudul nama bagiannya, tanpa breadcrumb.
2. Halaman anak selalu punya breadcrumb `Bagian / Halaman`, dan ujung breadcrumb sama persis dengan judul halaman.
3. Nama seperti `myapp/dev` ditulis utuh sebagai satu bagian breadcrumb, tidak dipecah.
4. Halaman tab di bagian utama berjudul nama tab-nya (mis. "Access requests", "Agent rules", "Alerts"), dengan breadcrumb `Bagian / Tab`. Tab default (mis. "Log") memakai judul bagian.
5. Halaman akun (Signed-in devices) memakai `Account / Halaman`.
6. Halaman satu-tugas yang berdiri sendiri (Sign in, Create vault password, Unlock, Authorize cfs, You're signed in) tanpa breadcrumb.
7. `<title>` browser sama dengan judul halaman.

## Riwayat akses per secret
Tab "Access history" di tiap secret (di sebelah "Values"):
- Ringkasan: jumlah pembukaan 30 hari, jumlah orang dan app yang pernah membuka, pembuka terakhir, dan jumlah orang yang pernah membuka tapi sudah tidak punya akses.
- "Siapa yang pernah melihat nilai saat ini": per orang atau app, jumlah buka, terakhir dibuka, dan akses sekarang (baris yang sudah dikeluarkan ditandai).
- Log lengkap untuk secret itu: waktu, siapa, versi, aksi, alasan, hasil, dengan filter.
- Dipakai setelah mencabut anggota: layar "Re-locking a group" memuat daftar nilai yang pernah dibuka orang itu, supaya diganti di sumbernya.
- Data diambil dari audit log yang sama. "Opened" berarti ciphertext diambil; server tidak melihat dekripsi.

## Layar kondisi dan pemulihan
Wrong password (dengan sisa percobaan), Access denied, Not in the group yet (dengan "Ask for access"), Session ended, Auto-lock warning, Empty state, Forgot password.
Lupa password: pengguna membuat password dan kunci baru, admin memverifikasi kode sidik jari kunci baru lewat jalur lain (telepon atau bertemu), lalu membungkus ulang kunci grup untuk kunci baru itu. Verifikasi wajib agar akun kerja yang diambil alih tidak bisa meminta akses.
Change vault password hanya mengganti kunci pembungkus private key, bukan kuncinya, sehingga akses ke grup tidak berubah.

## Verifikasi saat lupa password (web, tanpa kanal telepon di aplikasi)
Empat lapis, semuanya di web:
1. **Login ulang segar.** Permintaan reset hanya diterima jika pemohon baru masuk lewat Cloudflare Access (dalam 5 menit terakhir), jadi lewat MFA dari penyedia login.
2. **Kode empat kata, diketik admin.** Layar Forgot menampilkan kode pendek yang diturunkan dari public key baru pemohon (mis. `anchor-velvet-kiwi-sixty`). Pemohon mengirimnya ke admin lewat kanal yang mereka percayai (DM, chat, atau suara), bukan lewat permintaan itu. Admin mengetik kode itu di layar "Give access again"; tombol baru aktif jika cocok dengan kode kunci yang menunggu. Kotak centang tidak dipakai.
3. **"Apakah ini kamu?"** Pemohon asli menerima email dan notifikasi di perangkat lain yang sedang masuk, dengan tombol "Bukan saya, batalkan". Membatalkan membuang permintaan dan memberi tahu admin.
4. **Kunci pemulihan opsional** (24 kata, ditampilkan sekali di Setup). Pemilik kunci bisa memulihkan vault sendiri tanpa admin, lalu mendapat kunci pemulihan baru. Dilewati: jalur admin di atas yang berlaku.

Layar: Forgot (kode), Give access again (input kode), Was this you? (dari email), Setup: save your recovery key, Use your recovery key. "Unlock" dan "Wrong password" memuat tautan ke Forgot dan ke kunci pemulihan.

## Keluar (sign out) dan kunci vault
Setiap layar aplikasi punya dua tombol di sidebar, di bawah kotak pengguna:
- **Lock vault:** membuang kunci terbuka dari memori browser, kembali ke layar Unlock. Sesi Access tetap hidup.
- **Sign out:** mengakhiri sesi Cloudflare Access (endpoint `/cdn-cgi/access/logout` di hostname yang sama), membuang kunci dari memori, lalu menuju layar Sign in. Sesi CLI tidak ikut berakhir; dicabut terpisah di "Signed-in devices".

## Access kit (bot dan agent)
- Kit adalah kredensial bot: gabungan `role_id`, `secret_id`, dan private key. Tanpa kit, bot tidak bisa masuk atau membuka secret. Ditampilkan sekali. Server hanya menyimpan hash `secret_id` dan setengah publik kunci.
- Bentuk kit: **satu teks** (`cfskit1_...`) yang diisi ke environment variable `CFS_KIT`, bukan file wajib. Unduh sebagai file tetap tersedia. CLI membaca `CFS_KIT` otomatis; host dari `.cfs.json` atau `CFS_HOST`.
- Alur layar: Details, Save the kit, Connect it, Check it works. Layar "Kit ready" punya tab tujuan (GitHub Actions, Server atau Docker, AI agent, Laptop saya untuk uji) berisi langkah bernomor dan perintah siap salin.
- `cfs whoami` mencetak identitas yang sedang dipakai (`agent-billing · AI agent · signed in`). Status "Waiting for first sign-in" di UI menjadi hijau saat bot pertama kali masuk.

## Status implementasi (2026-11-21)
- `packages/core` sudah ada dan teruji (6 tes): envelope AES-256-GCM dengan AAD, pembungkus DEK ECDH P-256 + HKDF (ala ECIES), kunci privat dikunci password vault (PBKDF2-SHA256 600k), format kit `cfskit1_`, rantai hash audit, kode sidik jari.
- Perubahan dari desain: kode sidik jari sementara berupa 4 grup heksadesimal (`3FA9-81C2-D07B-6E54`), bukan empat kata, karena daftar kata belum dipilih. Ganti bila daftar kata sudah ada.
- Skema D1 awal ada di `apps/api/migrations/0001_init.sql` (identity, app_role, keyring, secret, policy, session, audit). Belum ada tabel untuk access request, alert, dan pengaturan; menyusul bersama fiturnya.
- Urutan berikutnya: `api` (auth Access + sesi, CRUD secret/keyring, audit), lalu `cli`, lalu `web`.
- `apps/api` sudah jalan (diuji lokal dengan wrangler + D1): verifikasi JWT Access, token `cfs_…` (login AppRole), sesi, vault setup, grup/keyring, secret (ciphertext saja, versi, daftar, hapus), kebijakan + assign, app/bot, audit berantai + `/audit/verify`.
- Semua rute ada di `/api/v1/*`. Di Cloudflare Access, lindungi hostname untuk UI, tetapi beri kebijakan Bypass untuk `/api/v1/*` (klien memakai token `cfs_…`; tanpa token, Worker sendiri meminta JWT Access).
- Belum ada: login CLI untuk manusia (device/loopback), access request, alert, rotasi keyring saat anggota dicabut, hash harian ke Slack/email, rentang CIDR (baru IP persis), rate limit login.
- `apps/cli` jalan (diuji lokal): `login` (device code), `unlock`, `lock`, `whoami`, `list`, `get`, `set`, `run`, `group create`, dan mode `CFS_KIT`. Keputusan di ADR 10 sampai 13.
- Belum ada di CLI: `group add-member` (tanpa ini app tidak bisa diberi kunci grup), `cfs init`, `cfs proxy`, `audit verify`, `deploy`. Layar web `/cli/authorize` belum ada, jadi persetujuan login sementara lewat `POST /api/v1/cli/approve`.
- Pada 2026-11-21 semua fitur sisa dipecah menjadi ADR 14 sampai 27 (`docs/adr/`). Implementasi mengikuti ADR; urutan kerja ada di `docs/adr/README.md`. Perbedaan dari desain di atas yang diputuskan di ADR: kode sidik jari menjadi empat kata BIP-39 (ADR 20), dan penyimpanan kunci CLI pindah ke keychain OS (ADR 25).


## Batas akses dan retensi
Admin dapat mengatur durasi maksimum permintaan (default 24 jam, maksimum 30 hari), durasi bawaan persetujuan (default 1 jam, tidak melebihi maksimum), dan retensi audit (default 365 hari, minimum 90 hari). Jika belum ada pengaturan, retensi memakai `AUDIT_RETENTION_DAYS` bila tersedia. Opsi kunci ulang setelah akses berakhir dicatat sebagai permintaan; rotasi belum otomatis.

## Bentuk konflik API
Respons HTTP 409 memuat `error` untuk manusia dan `code` stabil untuk klien, misalnya `version_conflict`, `group_rotating`, `group_key_changed`, dan `secret_deleted`. Daftar kode bersama tersedia di `packages/core`; klien harus menangani kode yang belum dikenal. Field tambahan seperti `current` atau `missing` tetap tersedia bila relevan.
