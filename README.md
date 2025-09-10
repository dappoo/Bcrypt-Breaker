# Bcrypt Breaker

Bcrypt Breaker is a multi-core bcrypt hash cracker tool written in Python. It uses the power of multiple CPU cores to efficiently attempt to crack bcrypt hashes using a wordlist.

## Fitur

- **Multi-core cracking**: Memanfaatkan banyak CPU cores untuk mempercepat proses cracking.
- **Bcrypt hash parsing**: Memecah dan mengidentifikasi informasi dari hash bcrypt.
- **Tampilan progres**: Menggunakan `tqdm` untuk menampilkan progres cracking.
- **Hasil penyimpanan**: Hasil cracking disimpan dalam file `result.txt`.

## Persyaratan

- Python 3.x
- Beberapa dependensi yang diperlukan (terdaftar di bawah)

## Instalasi

1. Clone repositori ini:

    ```bash
    git clone https://github.com/username/bcrypt-breaker.git
    cd bcrypt-breaker
    ```

2. Instal dependensi yang diperlukan:

    ```bash
    pip install -r requirements.txt
    ```

## Penggunaan

Untuk menggunakan tool ini, jalankan perintah berikut di terminal:

```bash
python bcrypt_breaker.py --hash <BCRYPT_HASH> --wordlist <WORDLIST_PATH>
