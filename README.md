# CIPHERBOARD — Simulasi AES-128 (Rijndael Block Simulator)

Aplikasi web edukatif untuk mensimulasikan algoritma **Advanced Encryption
Standard dengan panjang kunci 128-bit (AES-128)**, mode **ECB** untuk satu
blok data (16 byte / 128-bit). Aplikasi menampilkan **seluruh proses
perhitungan** — Key Expansion, Initial Round, Round 1–10, dan proses invers
untuk dekripsi — dalam bentuk **State Matrix 4×4** yang bisa dibuka/tutup
per ronde.

Seluruh algoritma AES (SubBytes, ShiftRows, MixColumns, Key Expansion, dan
operasi inversnya) **diimplementasikan sendiri dari nol**, baik di
JavaScript (`aes.js`, dipakai aplikasi web) maupun di Python
(`aes_reference.py`, dipakai sebagai alat verifikasi independen). Tidak ada
library kriptografi pihak ketiga (CryptoJS, dsb.) yang dipakai sebagai
implementasi utama.

---

## 1. Struktur Proyek

```
project-aes/
├── index.html        ← struktur halaman & form input
├── style.css          ← seluruh styling (tema, layout, warna State Matrix)
├── aes.js             ← implementasi algoritma AES-128 (murni JS, dengan logging tiap langkah)
├── app.js             ← logika UI: validasi input, render tabel State Matrix, navigasi ronde
├── aes_reference.py    ← implementasi referensi AES-128 dalam Python (verifikasi & bantu perhitungan manual)
├── test_aes.js         ← skrip pengujian aes.js terhadap test vector resmi FIPS-197
└── README.md           ← dokumen ini
```

---

## 2. Cara Menggunakan Aplikasi

### 2.1 Enkripsi
1. Pastikan tombol **ENCRYPT** pada bagian "Operasi" aktif (default).
2. Pilih format input plaintext:
   - **Teks**: ketik teks biasa, maksimal 16 karakter (contoh:
     `ATTACKATDAWN12XY`). Jika kurang dari 16 karakter, sisanya otomatis
     di-*pad* dengan byte `0x00`.
   - **Hex**: ketik langsung 32 karakter heksadesimal (16 byte), contoh:
     `3243f6a8885a308d313198a2e0370734`.
3. Isi **Kunci AES-128** sebagai 32 karakter heksadesimal (16 byte),
   contoh: `2b7e151628aed2a6abf7158809cf4f3c`.
   Atau klik ikon 🔄 di samping kolom kunci untuk membuat kunci acak.
4. Klik **JALANKAN ENKRIPSI**.
5. Hasil **Ciphertext (Hex)** akan tampil di kotak hasil — klik ikon salin
   untuk menyalinnya.
6. Di panel kanan akan muncul seluruh tahapan perhitungan:
   - **Key Expansion** — state awal kunci, proses W[0]..W[43] (bisa
     dibuka lewat tombol "Tampilkan proses lengkap"), dan hasil RK0–RK10.
   - **Initial Round** — AddRoundKey dengan RK0.
   - **Round 1 s/d Round 9** — SubBytes → ShiftRows → MixColumns →
     AddRoundKey, masing-masing dengan tabel *sebelum* dan *sesudah*.
   - **Round 10 (Final)** — SubBytes → ShiftRows → AddRoundKey (RK10,
     tanpa MixColumns) → Ciphertext akhir.

### 2.2 Dekripsi
1. Klik tombol **DECRYPT** pada bagian "Operasi".
2. Masukkan **Ciphertext** sebagai 32 karakter heksadesimal.
3. Isi **Kunci AES-128** yang sama dengan kunci saat enkripsi.
4. Klik **JALANKAN DEKRIPSI**.
5. Hasil **Plaintext (Hex)** akan tampil, beserta seluruh tahapan invers:
   AddRoundKey (RK10) → Round 9 s/d Round 1 (InvShiftRows → InvSubBytes →
   AddRoundKey → InvMixColumns) → Final Round/Ronde 0 (InvShiftRows →
   InvSubBytes → AddRoundKey dengan RK0).

### 2.3 Navigasi & Tampilan Detail
- **Toggle "Tampilkan detail proses perhitungan"** — nyalakan/matikan
  untuk menampilkan atau menyembunyikan seluruh panel State Matrix (hasil
  akhir tetap selalu tampil).
- **Indikator ronde (breadcrumb)** di bagian atas panel hasil — klik salah
  satu chip (misalnya "Round 3") untuk langsung membuka & scroll ke bagian
  tersebut.
- **Klik judul setiap section** (misalnya "Round 1") untuk
  membuka/menutup (collapse/expand) rinciannya.
- **Sel yang berubah** pada State Matrix "Sesudah" diberi highlight warna
  berbeda dibanding sel yang nilainya tetap sama dengan sebelumnya.
- Warna label operasi (SubBytes/ShiftRows/MixColumns/AddRoundKey)
  konsisten dengan legenda warna di panel kiri.
- Tombol **RESET** mengosongkan seluruh input dan hasil.

### 2.4 Validasi Input
Aplikasi akan menampilkan pesan kesalahan (bukan meng-crash) apabila:
- Plaintext teks lebih dari 16 karakter.
- Plaintext/ciphertext mode hex bukan 32 karakter heksadesimal yang valid.
- Kunci bukan 32 karakter heksadesimal yang valid.

---

##  Contoh Nilai Uji (FIPS-197)

Gunakan nilai berikut untuk verifikasi cepat aplikasi:

|           Plaintext (hex)          |               Key (hex)            |  Ciphertext (hex) yang diharapkan  |
|------------------------------------|------------------------------------|------------------------------------|
| `3243f6a8885a308d313198a2e0370734` | `2b7e151628aed2a6abf7158809cf4f3c` | `3925841d02dc09fbdc118597196a0b32` |
| `00112233445566778899aabbccddeeff` | `000102030405060708090a0b0c0d0e0f` | `69c4e0d86a7b0430d8cdb78070b4c55a` |

---