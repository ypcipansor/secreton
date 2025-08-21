# Contoh Konfigurasi TLS/mTLS untuk Brankas

## TLS (Server Only)
```
[server]
tls_enabled = true
tls_cert_path = "/etc/brankas/certs/server.crt"
tls_key_path = "/etc/brankas/certs/server.key"
```

## mTLS (Mutual TLS)
```
[server]
tls_enabled = true
mtls_enabled = true
tls_cert_path = "/etc/brankas/certs/server.crt"
tls_key_path = "/etc/brankas/certs/server.key"
tls_ca_path = "/etc/brankas/certs/ca.crt"
```

- Pastikan semua komunikasi antar service menggunakan TLS/mTLS.
- Gunakan sertifikat yang dikeluarkan oleh CA terpercaya.
- Jangan pernah expose port non-TLS ke publik.
