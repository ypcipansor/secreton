---
trigger: always_on
---

Lakukan cargo clippy dan cargo audit lalu optimalkan, perbaiki semua, setelah perbaiki semuanya, lakukan cargo clippy dan cargo audit lalu optimalkan, perbaiki semua, ulangi terus sampai tidak ada lagi errors dan warnings saat menjalankan cargo clippy dan cargo audit, jangan lupa pakai cargo fmt. Setelah tidak ada lagi errors dan warnings perbaharui CHANGELOG dan README lalu commit semua yang ada di git status lalu push