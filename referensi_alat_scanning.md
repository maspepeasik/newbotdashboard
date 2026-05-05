# Referensi Alat Scanning

Dokumen ini menjelaskan perilaku scanning yang benar-benar diimplementasikan di project saat ini.

## Model Stage Runtime

Status yang terlihat di API dan dashboard:

1. Queued
2. Recon
3. Resolver
4. OriginIP
5. PortScan
6. ServiceScan
7. HTTPProbe
8. Fingerprint
9. WebDiscovery
10. VulnScan
11. TLSScan
12. Aggregation
13. AIAnalysis
14. Report
15. Done

Hanya stage `Recon` sampai `TLSScan` yang benar-benar menjalankan tool scanning. Stage setelahnya adalah pemrosesan internal untuk agregasi, AI, dan pembuatan PDF.

## Urutan Stage Aktual

Urutan yang dipakai code sekarang:

```text
Recon -> Resolver -> OriginIP -> PortScan -> ServiceScan -> HTTPProbe
-> Fingerprint -> WebDiscovery -> VulnScan -> TLSScan
-> Aggregation -> AIAnalysis -> Report -> Done
```

Ini penting karena:

- `WebDiscovery` memakai hasil `HTTPProbe`
- `VulnScan` memakai URL yang sudah dikurasi oleh `WebDiscovery`
- `wpscan` dan `joomscan` bergantung pada hasil `Fingerprint`
- `TLSScan` memilih target HTTPS terbaik dari hasil `HTTPProbe`

## Tahapan dan Alat

| # | Tahap | Alat | Ringkasan |
|---|---|---|---|
| 1 | `Recon` | `subfinder`, `assetfinder`, `anew`, opsional `amass` | Enumerasi subdomain dan deduplikasi |
| 2 | `Resolver` | `dnsx`, fallback Python | Resolusi DNS dan peta IP-host |
| 3 | `OriginIP` | `curl`, probing DNS | Mencari origin host di balik CDN/WAF |
| 4 | `PortScan` | `naabu`, fallback socket | Scan port TCP |
| 5 | `ServiceScan` | `nmap` | Fingerprint service dan versi |
| 6 | `HTTPProbe` | ProjectDiscovery `httpx`, fallback `curl` | Inventaris endpoint web aktif |
| 7 | `Fingerprint` | `whatweb`, `wafw00f`, `webanalyze` | Deteksi teknologi dan WAF |
| 8 | `WebDiscovery` | `gau`, `katana` | Ekspansi URL dari endpoint aktif |
| 9 | `VulnScan` | `nuclei`, opsional `nikto`, kondisional `wpscan`, `joomscan` | Scan kerentanan utama |
| 10 | `TLSScan` | `testssl.sh`, opsional `sslyze`, fallback `openssl` | Analisis TLS dan sertifikat |

## Fast Mode vs Deep Mode

### Fast Mode

- `naabu_top_ports=1000`
- `nmap_flags=-sV -sC`
- `nmap_max_ports=50`
- `katana_depth=2`
- `max_discovered_urls=150`
- target `nuclei` maksimal 4 URL
- `amass`, `nikto`, `dirsearch`, dan `s3scanner` tidak dipaksa aktif

### Deep Mode

- `naabu_top_ports=full`
- `naabu_rate=2000`
- `nmap_flags=-sV -sC --script vuln`
- `nmap_max_ports=200`
- `katana_depth=4`
- `max_discovered_urls=500`
- target `nuclei` maksimal 12 URL
- mengaktifkan `amass`, `nikto`, `dirsearch`, dan `s3scanner`

### Nuansa penting

Deep mode memperluas cakupan eksekusi, tetapi hasil report tetap dibatasi agar fokus.

Contoh:

- deep mode bisa menjalankan `nuclei` dengan severity `critical,high,medium,low`
- tetapi parser reportable finding saat ini masih menyimpan `critical`, `high`, dan `medium`
- setelah itu masih ada filter tambahan di `Normalizer`

## Catatan Per Tahap

### Recon

- `subfinder` dan `assetfinder` berjalan paralel
- `amass` memakai direktori data per-scan agar tidak bentrok
- domain target utama selalu dimasukkan ke daftar subdomain akhir

### Fingerprint

- `whatweb`, `wafw00f`, dan `webanalyze` berjalan paralel
- hasil fingerprint digabung dengan teknologi yang sudah terdeteksi dari `httpx`
- jika WAF terdeteksi, backend menambahkan limitation pada hasil scan

### WebDiscovery

- hanya URL yang masih in-scope yang dipertahankan
- URL dinormalisasi dan dideduplikasi
- URL dengan query string atau path yang lebih dalam diprioritaskan
- hasil dibatasi oleh `max_discovered_urls`

### VulnScan

Perilaku stage ini saat ini:

- `nuclei` dijalankan jika binary tersedia
- `nikto` hanya dijalankan jika diaktifkan
- `wpscan` hanya jalan jika WordPress terdeteksi
- `joomscan` hanya jalan jika Joomla terdeteksi
- scan CMS hanya diantrekan pada deep mode

Jika template `nuclei` tidak ditemukan, stage mencoba mengunduh template lebih dulu.

### TLSScan

- memilih beberapa kandidat target HTTPS terbaik
- memakai `testssl.sh` sebagai sumber utama
- fallback ke `openssl` bila perlu
- `sslyze` hanya dipakai sebagai validasi sekunder
- hasil TLS yang tidak konklusif masuk ke limitation, bukan finding utama

## Kebijakan Filter dan Reporting

Report final sengaja bukan dump mentah dari semua output scanner.

### Nuclei

Beberapa kelas finding yang dikeluarkan dari report:

- template inventory DNS dan RDAP
- informasi sertifikat yang sudah dicakup oleh TLS scan
- template header security yang terlalu noisy
- duplikasi deteksi WAF

### Nikto

Parser hanya mempertahankan finding yang terlihat punya arti praktis. Banyak line informasional dan metadata server dibuang.

### TLS

Line informasional dan hasil yang tidak actionable disaring. Kelemahan TLS yang lebih jelas dan attack class yang dikenal akan lebih diprioritaskan.

### Missing security headers

Header hardening yang hilang tidak dijadikan finding utama. Sistem mencatatnya sebagai limitation atau note supaya report tetap fokus pada issue yang lebih bermakna.

## Tahap Setelah Scanning

Setelah semua tool selesai:

1. `ResultAggregator` menggabungkan finding dari port, TLS, `nuclei`, dan `nikto`
2. `Normalizer` menambah remediation, melakukan dedupe, filter noise, dan menghitung risk
3. `GroqAI.analyze()` menulis section report
4. `GroqAI.enrich_findings()` memperbaiki deskripsi finding prioritas
5. `ReportBuilder` dan `PDFGenerator` membuat PDF final

## Aturan Perawatan Dokumen

Jika dokumen ini berbeda dengan perilaku source code, anggap source code sebagai acuan utama lalu perbarui dokumentasi ini. File yang paling penting untuk dicek:

- `backend/core/job_manager.py`
- `backend/pipeline/*.py`
- `backend/analysis/result_aggregator.py`
- `backend/analysis/normalizer.py`
- `backend/analysis/groq_ai.py`
