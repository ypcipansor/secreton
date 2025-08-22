# Contoh Konfigurasi TLS/mTLS untuk Secreton

## TLS (Server Only)
```
[server]
tls_enabled = true
tls_cert_path = "/etc/secreton/certs/server.crt"
tls_key_path = "/etc/secreton/certs/server.key"
```

## mTLS (Mutual TLS)
```
[server]
tls_enabled = true
mtls_enabled = true
tls_cert_path = "/etc/secreton/certs/server.crt"
tls_key_path = "/etc/secreton/certs/server.key"
tls_ca_path = "/etc/secreton/certs/ca.crt"
```

- Pastikan semua komunikasi antar service menggunakan TLS/mTLS.
- Gunakan sertifikat yang dikeluarkan oleh CA terpercaya.
- Jangan pernah expose port non-TLS ke publik.
