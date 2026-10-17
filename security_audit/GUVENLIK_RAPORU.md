# AegisVault v4.0.0 — Güvenlik Denetim Raporu

**Tarih:** 17 Ekim 2026
**Kapsam:** Tüm Python modülleri (`app.py`, `military_vault.py`, `vault_storage.py`, `military_audit.py`, `crypto_utils.py`, `crypto_chat.py`, `live_p2p_chat.py`, `airgap_crypto.py`, `steganography.py`, `crypto_portfolio.py`, `updater.py`)
**Yöntem:** Kaynak kod analizi (statik) + çalıştırılabilir PoC kanıtları (dinamik)
**Ortam:** Python 3.14.7, cryptography 50.0.0, Linux (Windows'a özgü yollar ayrıca belirtildi)

Bu denetimde **20 bulgu (V-01…V-20) + derin kriptografik analizde eklenen 2 bulgu (W-01, W-02)** tespit edilmiş; tamamı çalıştırılabilir PoC ile kanıtlanmıştır (V-18 kısmi kanıt: API sözleşme düzeyi). 18 PoC `security_audit/` dizininde olup `./security_audit/run_all.sh` ile tek seferde çalıştırılabilir. Ham çıktılar: `/tmp/opencode/aegis_poc/all_poc_output.log`. PoC'lerin doğrulama metodolojisi için bkz. Bölüm 6, kriptografik derin analiz için Bölüm 7, mimari değerlendirmesi için Bölüm 8, PR katkıları ve teknoloji önerileri için Bölüm 9-10.

---

## 1. Yönetici Özeti

| # | Bulgu | Şiddet | Kanıt |
|---|-------|--------|-------|
| V-01 | GUI katmanı savunmaları (rate-limit / scorched-earth / DMS) offline kasa kırma saldırısına karşı tamamen etkisiz | **Kritik** | PoC_01A |
| V-02 | `.security_state.json` HMAC doğrulaması yok sayılıyor; anahtar kamuya açık veriden türetildiği için **sessiz** kurcalama mümkün | **Kritik** | PoC_01B |
| V-03 | `_failed_attempts` global sayacı profiller arası sızıyor → **yanlış kasayı imha ediyor** | **Kritik** | PoC_01C |
| V-04 | PQ-Hybrid KEM el sıkışması kimliksiz → saldırgan oturum anahtarını kendisi belirliyor (E2EE hijack) | **Kritik** | PoC_03 |
| V-05 | "Tamper-evident" audit trail yeniden yazılabiliyor / silinebiliyor | **Yüksek** | PoC_02 |
| V-06 | `emergency_zeroize_vault()` path traversal ile keyfi dosya imhası | **Yüksek** | PoC_04 |
| V-07 | Duress (baskı) parolası, kilit açma süresi yan kanalıyla tespit edilebiliyor | **Yüksek** | PoC_05 |
| V-08 | Zeroization sahte başarı raporu: hata yutma + CWD bağımlılığı → sırlar diskte kalırken "imha edildi" deniyor | **Yüksek** | PoC_06 |
| V-09 | Dead-Man's Switch baypası (`last_checkin > 0` koşulu + state manipülasyonu) | **Yüksek** | PoC_01B/B3 |
| V-10 | Auto-updater imzasız/hash'siz ikili çalıştırıyor; SHA-256 doğrulaması ölü kod | **Yüksek** | PoC_09 |
| V-11 | FIPS 140-3 POST sonucu uygulanmıyor; audit'e koşulsuz "100% Passed" yazılıyor | **Orta** | PoC_07 |
| V-12 | "Anti-Backdoor Shield" alt-dizge filtresiyle atlatılıyor; SHA3-256 özeti hiçbir yerde doğrulanmıyor | **Orta** | PoC_08 |
| V-13 | Donanım parmak izi hostname + mimari + env'den türetiliyor (publik, sahtelenebilir, 96-bit) | **Orta** | PoC_10A |
| V-14 | Decoy kasa `_decoy.mvat` dosya adıyla ifşa oluyor → plausible deniability çöküyor | **Orta** | PoC_10B |
| V-15 | P2P sohbette gönderici kimliği kriptografik olarak doğrulanmıyor; replay koruması yalnızca oturum belleği | **Orta** | PoC_11 |
| V-16 | `decrypt_message()` epoch/nonce doğrulaması yapmıyor (stego/QR yollarında replay koruması yok) | **Düşük** | PoC_12 |
| V-17 | Portföy modülünde doğrulanmamış adres URL'ye gömülüyor (path/query manipülasyonu) | **Düşük** | PoC_13 |
| V-18 | "RAM zeroization" iddiası aşırı (Python `str` değiştirilemez; kopyalar kalır) | Bilgi | PoC_15 (kısmi) |
| V-19 | Profil adı sanitizasyonu Unicode `isalnum` → homoglif + sessiz dosya çakışması (veri kaybı) | **Orta** | PoC_14 |
| V-20 | POST scrypt KAT'ı üretim parametreleriyle (N=2^15) değil N=1024 ile test ediliyor | **Orta** | PoC_16 |
| W-01 | ZK topic bir parola doğrulayıcıdır (HMAC, KDF'siz); varsayılan oda anahtarı kaynakta sabit → varsayılan odalar tamamen açık, zayıf anahtarlar offline sözlükle kırılır | **Yüksek** | PoC_17 |
| W-02 | Özel PQ-Hybrid KEM'de CCA/FO dönüşümü ve katsayı doğrulaması yok: bozuk kapsül sessizce farklı deterministik anahtar üretir (desenkronizasyon; key confirmation yok) | **Orta** | PoC_18 |

**Olumlu tespitler:** AES-256-GCM + AAD bağlama doğru uygulanmış (nonce/ salt CSPRNG, header AAD'ye bağlı — bit-flip reddi çalışıyor); scrypt parametreleri pre-auth sınırlandırılmış (OOM DoS engelli); SSS implementasyonu matematiksel olarak doğru; sırların hiçbiri düz metin diske yazılmıyor.

---

## 2. Bulgu Detayları

### V-01 — Offline saldırıya karşı savunma katmanları etkisiz (Kritik)

**Konum:** `vault_storage.py:347-451` (`unlock_vault`)

**Açıklama:** README'nin tehdit modelinde "Stolen `.mvat` file + multi-GPU hashcat cluster" ve "Persistent Brute-Force / Seizure" senaryoları; rate-limit, Scorched-Earth wipe ve DMS ile savunulduğu iddia ediliyor. Ancak tüm bu mekanizmalar **yalnızca `unlock_vault()` GUI katmanında** yaşar. Kasa dosyası (`MVAULT` + scrypt + AES-256-GCM) kendi kendine yeterlidir; saldırgan `MilitaryVault.decrypt()`'i (veya hashcat'i) doğrudan çalıştırır.

**PoC kanıtı (PoC_01A):**
```
[A] MilitaryVault.decrypt ile 10 parola tahmini yapildi (hashcat senaryosu).
[A] Rate-limit var mi? HAYIR
[A] Scorched-earth wipe oldu mu? False
[A] Kasa dosyasi duruyor mu? True
[A] Audit'e AUTH_FAILURE yazildi mi? False
```

**Etki:** Sayaçlar, wipe ve DMS dosya çalındığı anda devre dışı. Kalan tek savunma scrypt (32 MB) + donanım bağlama/keyfile'dır; bu da V-13 ile zayıflatılmaktadır.

**Öneri:** "Scorched-earth/DMS" iddialarınızı offline saldırı için gerçekçi biçimde revize edin; gerçek koruma için kasa anahtarını TPM/HSM'e bağlayın veya ikinci faktörü zorunlu kılan ayrı bir master-key katmanı (ör. Argon2id + hardware-backed key) kullanın. Kullanıcıya "offline kırma savunması budur" mesajını açıkça iletin.

---

### V-02 — Güvenlik durumu HMAC'i doğrulanmıyor + anahtar kamuya açık (Kritik)

**Konum:** `vault_storage.py:69-94` (özellikle `:81` doğrulama, `:92` koşulsuz `return state`)

**Açıklama:** HMAC uyuşmazlığında yalnızca audit kaydı atılıyor, ardından **kurcalanmış state yine döndürülüyor**. Ayrıca HMAC anahtarı `get_hardware_fingerprint()`'ten türetilir; bu değer hostname + mimariden hesaplandığından saldırgan **geçerli HMAC üretip kurcalamayı tamamen sessiz** yapabilir.

**PoC kanıtı (PoC_01B):**
```
[B1] Naif kurcalama: _load_security_state() kurcalanmis degeri dondurdu: failed_attempts=99
     -> SECURITY_STATE_TAMPER uretildi mi? True (loglanir ama state yine kullanilir!)
[B2] Gecerli HMAC ile SESSIZ kurcalama + sayac sifirlama:
     -> Gercek hatali deneme: 9 (wipe esigi=3). Rate-limit'e takilan: 0
     -> Yeni SECURITY_STATE_TAMPER olayi: False (tamamen SESSIZ)
     -> Kasa hala duruyor mu? True
```

**Ek:** `_load_security_state()` herhangi bir istisnada `{"profiles": {}}` döndürür (`:93-94`) — state dosyasını silmek/bozmak da tüm politikaları sıfırlar.

**Öneri:**
1. HMAC uyuşmazlığında `state` yerine **fail-closed** davranın (boş state döndürün + DMS/wipe politikalarını en katı değere sabitleyin + kullanıcıya görünür uyarı).
2. HMAC anahtarını donanım parmak izi yerine **kasadan türetilen bir sır** veya DPAPI/Keychain/TPM ile saklanan rastgele anahtar yapın.
3. Sayaçları aynı dosyada değil, silinemez/eşzamanlı erişim denetimli ayrı bir konumda ek olarak saklayın.

---

### V-03 — Global sayaç profiller arası sızıyor → yanlış kasa imhası (Kritik)

**Konum:** `vault_storage.py:30` (`_failed_attempts` modül global'i), `:366` (`max(_failed_attempts, ...)`), `:429`

**Açıklama:** Hatalı deneme sayacı modül seviyesinde global tutulur ve `unlock_vault` içinde `persisted_fails = max(_failed_attempts, state)` ile **her profilin** sayacına eklenir. Bir profilde yapılan hatalı denemeler, başka bir profilin Scorched-Earth eşiğini tetikler.

**PoC kanıtı (PoC_01C) — bu bulgu PoC yazımı sırasında canlı olarak keşfedildi:**
```
[C] profil_A'da 2 hatali deneme yapildi (global sayac=2)
[C] profil_B'de SADECE 1 hatali deneme yapildi -> SCORCHED-EARTH PROTOCOL TRIGGERED: 3/3 failed attempts reached.
[C] profil_B kasasi imha edildi mi? True
[C] Audit kaniti: 'Failed attempts (3) reached Scorched-Earth limit (3). Vault shredded.'
```

**Etki:** A kasasında 2 kez yazım hatası yapan kullanıcı, B kasasında 1 hatalı denemede **B kasasını kalıcı olarak imha eder**. Kullanıcı hatası → veri kaybı; ayrıca yerel bir saldırgan, kurbanın başka profilini 2 kez kasten başarısız yapıp hedef profili tek denemeyle imha ettirebilir (DoS).

**Öneri:** Sayacı `profile_name` bazında izole edin; global değişkeni kaldırın; wipe kararını yalnızca o profilin kalıcı sayacıyla verin.

---

### V-04 — PQ-Hybrid KEM handshake hijack (Kritik)

**Konum:** `live_p2p_chat.py:147-177` — özellikle `:164-168` (gelen ilk `[PQ-KEM-ACK]` hiçbir bağ/imza kontrolü olmadan kabul ediliyor)

**Açıklama:** `[PQ-KEM-SYN]` yayınını gören ve `base_room_key`'i bilen her akran, kurbanın geçici PQ açık anahtarına **kendisi** kapsülleyip ACK gönderebilir. Kurban, gelen ilk ACK'i kabul ederek `room_key`'i saldırganın seçtiği `SHA3(base|PQ:shared)` değerine ratchet eder. Kapsül ↔ SYN ↔ gönderici arasında hiçbir kriptografik bağ yoktur.

**PoC kanıtı (PoC_03):**
```
[2] Saldırgan kurbanin acik anahtarina KENDISI kapsulleme yapiyor
    Saldirganin hesapladigi ratchet anahtari: 463a5fc8946173ec666cfc9288278321...
[3] Kurbanin yeni room_key'i: 463a5fc8946173ec666cfc9288278321...
    [!!] Kurban ve saldirgan AYNI ratchet anahtarini paylasiyor
[5] Cozulen duz metin: '25d413ea:victim: GIZLI: Yarın 21:00'de teslimat noktasına gelin.'
```

**Etki:** "Post-quantum korumalı" kanalın anahtarını saldırgan belirler; kurbanın tüm sonraki mesajları saldırgan tarafından okunur. README'deki PQ-KEM ratchet güvenlik iddiası çürütülür.

**Öneri:** Kapsülü `base_room_key` ile HMAC'leyip SYN göndericisine bağlayın (ör. `HMAC(K=AES_key, transcript)` içeren AEAD associated data); aynı SYN'e ikinci ACK'i reddedin; ratchet'i sıfırlayan mesajları (SYN/ACK) `session_id` başına bir kez kabul edin; ideal olarak imzalı ephemeral anahtar (Ed25519) kullanın.

---

### V-05 — Audit trail tamper-evident değil (Yüksek)

**Konum:** `military_audit.py:190-268`

**Açıklama:** Zincir düz SHA-256 hash'lerinden oluşur; HMAC/imza/trusted anchor yoktur. Dosya yazma yetkisi olan saldırgan tüm zinciri yeniden hesaplayabilir. Dosya silindiğinde `verify_integrity()` `(True, "Audit log is empty.", 0)` döndürür (`:252-253`).

**PoC kanıtı (PoC_02):**
```
[+] Baslangic: VAULT_UNLOCK -> SECRET_EXFIL -> USUAL_OP (ok=True)
[!] SECRET_EXFIL silindi, zincir yeniden hesaplandi -> verify: ok=True
[!] Dosya tamamen silindi -> verify: ok=True | "Audit log is empty."
```

**Öneri:** Zinciri kurulumda üretilen ve TPM/DPAPI anahtarıyla korunan bir HMAC anahtarıyla imzalayın; her blokta `HMAC(K, prev_hash || block)` saklayın; boş/eksik dosyayı "şüpheli" sayın.

---

### V-06 — `emergency_zeroize_vault()` path traversal (Yüksek)

**Konum:** `military_audit.py:287-288` — `f"profiles/{profile_name}.mvat"` **ham adla** kuruluyor; komşu API `get_profile_files()` ise `:208`'de sanitize ediyor.

**PoC kanıtı (PoC_04):**
```
[+] Zararli profil adi: '../../../outside_poc04/gizli_belge'
[+] Ayni yol mu? True
[!] Hedef dosya hala var mi? False (imha edildi)
[!] Audit: 'DoD 5220.22-M 3-pass cryptographic zeroization completed. Vault files shredded.'
```

**Etki:** DMS/Scorched-Earth ve panic-zeroize akışları ham profil adı ile çağrıldığında `profiles/` dışındaki keyfi `.mvat` dosyaları imha edilebilir. Windows'ta `..\..\` ile aynı etki; profil adı kullanıcı girdisidir (`app.py:400`, `vault_storage.init_vault`) ve state dosyasına ham haliyle yazılır.

**Öneri:** `profile_name`'i tek bir ortak sanitize fonksiyonundan geçirin (veya `os.path.basename` + whitelist); hedef yolların `profiles/` kökü içinde kaldığını `os.path.realpath(...).startswith(root)` ile doğrulayın.

---

### V-07 — Duress parolası timing yan kanalıyla tespit edilebiliyor (Yüksek)

**Konum:** `vault_storage.py:385-426` (aday listesi sırası; gerçek kasa → decoy kasa); tetikleyici `app.py:556`

**Açıklama:** scrypt türetim sayısı parola türüne göre değişir: master = 1, duress = 3, yanlış = 4. Kilit açma süresi ölçülerek parola türü ayırt edilir.

**PoC kanıtı (PoC_05):**
```
MASTER : ort= 120.9 ms
DURESS : ort= 352.4 ms
WRONG  : ort= 472.8 ms
[!] Duress/Master sure orani: 2.91x
```

**Etki:** "Matematiksel ve görsel olarak ayırt edilemez" iddiası geçersiz. Cihaz üzerindeki malware veya fiziksel gözlemci, duress parolasının girildiğini anında anlar — baskı altındaki kullanıcı için tehlikeli.

**Öneri:** Tüm adaylar için sabit sayıda scrypt türetimi yapın (ör. her zaman 4 aday deneyin, başarıda bile) veya decoy/gizli anahtar şemasına geçin (tek şifreli container içinde iki plaintext — VeraCrypt tarzı); sabit-zaman davranışı sağlayın.

---

### V-08 — Zeroization sahte başarı raporu (Yüksek)

**Konum:** `military_audit.py:300-330`

**Açıklama:** Wipe döngüsündeki tüm istisnalar `except Exception: pass` ile yutulur; fonksiyon koşulsuz `True` döner ve audit'e "shredded" yazar. Ayrıca yollar CWD'ye göre çözülür.

**PoC kanıtı (PoC_06):**
```
[A] Kasa dosyasi salt-okunur (chmod 444): Fonksiyon donusu: True | Dosya hala diskte mi? True | Icerik degismedi mi? True
[A] Audit kaydi: 'DoD 5220.22-M 3-pass cryptographic zeroization completed. Vault files shredded.'
[B] Farkli CWD: ayni sekilde True + 'shredded' (gercek kasa yerinde)
```

**Ek not:** 3-geçişli üzerine yazma; SSD/CoW/journaling dosya sistemlerinde orijinal blokları garanti silmez. "DoD 5220.22-M uyumlu" ifadesi teknik olarak yanıltıcıdır.

**Öneri:** Her adımın sonucunu doğrulayın (dosya yok mu? boyut/hash kontrolü); hata durumunda `False` + CRITICAL audit; yolları uygulama köküne sabitleyin; DoD iddiasını "best-effort logical delete" olarak düzeltin veya tam-disk şifreleme şartı belirtin.

---

### V-09 — Dead-Man's Switch baypası (Yüksek)

**Konum:** `vault_storage.py:157` — `if dms_days > 0 and last_checkin > 0:`; state kurcalama V-02 ile birleşir.

**PoC kanıtı (PoC_01B3):**
```
[B3] dms_days=1, last_checkin_epoch=0 -> tetiklendi mi? False  (last_checkin > 0 koşulu 0'ı yutar)
```

**Etki:** Saldırgan `last_checkin_epoch`'u 0 yaparak veya tazeleyerek (geçerli HMAC ile sessiz) DMS'i süresiz askıya alır; UI'da politika "1 gün" görünmeye devam eder.

**Öneri:** `last_checkin == 0` / eksik değeri "check-in yapılmamış" olarak fail-closed değerlendirin; state bütünlüğü V-02 ile düzeltilmeli.

---

### V-10 — Updater imzasız ikili çalıştırıyor (Yüksek)

**Konum:** `updater.py:111-159`; çağrı `app.py:813` — `expected_sha256` hiçbir zaman verilmiyor (`:134` bu yüzden ölü kod).

**Açıklama:** Kabul kriteri yalnızca `MZ` sihirli baytları + ≥1 MB boyut. HTTPS allowlist, ele geçirilmiş bir GitHub deposunun/kötü niyetli release asset'inin ürettiği dosyayı engellemez.

**PoC kanıtı (PoC_09):**
```
[2] sys.exit(0) cagrildi -> basari yolu
[3] Calistirilan komut: ['cmd.exe', '/c', 'update_installer.bat']
[4] Diske yazilan sahte ikili: AegisVault_update.exe (2,000,002 bayt)
```

**Öneri:** Release'e `.sha256` ekleyip uygulamada **zorunlu** doğrulayın; tercihen Authenticode/`WinVerifyTrust` ile imza doğrulaması yapın; hash uyuşmazlığında kurulumu iptal edip kullanıcıya bildirin.

---

### V-11 — POST sonucu uygulanmıyor (Orta)

**Konum:** `app.py:78-81` (koşulsuz "100% Passed" audit), `app.py:621-624` (yalnızca rozet rengi)

**PoC kanıtı (PoC_07):**
```
[1] run_power_on_self_tests() -> all_passed = False
[2] app.py:79-81 birebir calistirildi -> audit: 'FIPS 140-3 Power-On Self Tests 100% Passed'
    Gercek sonuc ile audit kaydi CELISIYOR
```

**Öneri:** `all_passed=False` ise audit mesajını gerçek sonuca göre yazın ve kasa işlemlerini engelleyin (fail-closed); `all_passed=True` varsayılanını kaldırın.

---

### V-12 — Anti-Backdoor Shield baypası (Orta)

**Konum:** `military_audit.py:148-183`

**PoC kanıtı (PoC_08):**
```
[3] verify_runtime_backdoor_shield() sonucu: passed=True
    [!!] Arka kapi ve 'os.system(' iceren app.py TESPIT EDILMEDI
[4] Arka kapi gercekten calisti mi? True (Icerik: ARKA_KAPI_CALISTI)
[5] Donen SHA3-256 ozeti hicbir sabitle karsilastirilmiyor
```

**Nedenler:** (a) 5 literal alt-dizge filtresi `getattr(os, "sys"+"tem")` ile atlatıldı, (b) özet yalnızca mesaj metnine giriyor — pinned referans yok, (c) `app.py` taranan liste dışında.

**Öneri:** AST tabanlı analiz (ör. `ast` ile `Call` düğümleri) kullanın; beklenen SHA3-256 özetini derleme zamanında gömüp karşılaştırın (release imzası ile); `app.py` dahil tüm çalıştırılan modülleri kapsayın.

---

### V-13 — Donanım parmak izi sahtelenebilir (Orta)

**Konum:** `vault_storage.py:34-37`

**PoC kanıtı (PoC_10A):**
```
[+] Gercek parmak izi: dac95678d4f6676a185efaaf (32-hex'ten 24'ü = 96-bit)
[+] Saldırgan kurbanın hostname'ini ogrendi ve ayni degeri taklit etti: Kasa ACILDI
```

**Etki:** "Hardware-bound profile" iddiası yalnızca hostname + mimari + `COMPUTERNAME` env değerine dayanır; TPM/disk seri numarası/MAC kullanılmaz. Bu değerler loglardan/aktif cihazdan elde edilebilir; 96-bit kısaltma da kaba kuvvetle eşleştirilebilir.

**Öneri:** TPM 2.0 (`TPM2_MakeCredential`), Windows DPAPI makine anahtarı veya disk seri numarası + üretim sırasında kasadan türetilen rastgele bir `machine_secret` kullanın.

---

### V-14 — Decoy kasa dosya adıyla ifşa (Orta)

**Konum:** `vault_storage.py:211` (`_decoy.mvat`), `:319`

**PoC kanıtı (PoC_10B):**
```
[+] profiles/ dizin icerigi: ['.security_state.json', 'covert.mvat', 'covert_decoy.mvat', 'hwb.mvat']
```

**Etki:** README "matematiksel ve görsel olarak imkânsız" dese de dosya sistemine bakan bir adli incelemeci ikinci kasanın varlığını ilk saniyede görür; baskı uygulayıcısı "decoy'u değil gerçeğini ver" diye direkt hedefler. Ayrıca `is_decoy=True` durumu kasa içeriğinde de saklanır.

**Öneri:** İki kasa container'ını ayırt edilemez biçimde birleştirin (hidden volume yaklaşımı) ve/veya en azından nötr dosya adları kullanın; decoy varken gerçek kasanın boyut/erişim izleri ile ayrışmamasını sağlayın.

---

### V-15 — P2P: gönderici kimliği doğrulanmıyor, replay koruması oturum belleğinde (Orta)

**Konum:** `live_p2p_chat.py:117-144`

**PoC kanıtı (PoC_11):**
```
[!] Kurbanin gordugu gonderici : 'AlicE'   (gercek gonderici: saldirgan)
[2] YENIDEN BASLATILMIS oturum ayni paketi teslim etti mi? True
```

Mesaj kimliği (`sender`) yalnızca şifreli metnin içinde taşınır; imza yoktur. `room_key`'i bilen herkes herhangi bir kullanıcı adıyla mesaj gönderebilir. Nonce cache (`maxlen=512`) ve ±600 sn penceresi **yalnızca bellekte**dir; uygulama yeniden başlatıldığında aynı paket yeniden teslim edilir.

**Öneri:** Her mesaja Ed25519 imzası ekleyin (username → public key pinning/TOFU); nonce cache'i diske veya monotonik sayaç tabanlı ratchet'e bağlayın.

---

### V-16 — `decrypt_message()` replay doğrulaması yapmıyor (Düşük)

**Konum:** `crypto_chat.py:44-55`

**PoC kanıtı (PoC_12):**
```
[2] 6 yil eski epoch ile hazirlanmis token kabul edildi: "2020'DEN KALMA ESKI MESAJ" | Reddedildi mi? HAYIR
[5] Ayni stego PNG defalarca 'acildi': ... | esit=True
```

Epoch/nonce alanları decrypt sonrası hiç kontrol edilmez; replay savunması yalnızca `live_p2p_chat` içindedir. Steganografi (`steganography.py:147`) ve QR (`airgap_crypto.py:89`) aynı token'ı doğrulamasız kabul eder — yakalanan bir QR/görsel sınırsız yeniden oynatılabilir.

**Öneri:** Anti-replay doğrulamasını `decrypt_message` seviyesine taşıyın (opsiyonel `max_age_s` parametresi) ve tüm çağrı yollarında uygulayın.

---

### V-17 — Portföy URL enjeksiyonu (Düşük)

**Konum:** `crypto_portfolio.py:64` — `f"https://blockchain.info/q/addressbalance/{addr}"`

**PoC kanıtı (PoC_13):**
```
[1] validate_crypto_address(malicious) -> False (Invalid Bitcoin address!)
[2] Fonksiyon dogrulama YAPMADAN istegi atti: https://blockchain.info/q/addressbalance/bc1qxyz/../../admin?redirect=evil#frag
```

Adres alanı doğrulanmadan URL yoluna konur; `?`, `/`, `#` içeren girdiler istek yolunu/sorgusunu değiştirir (host sabit olduğundan SSRF değil, istek manipülasyonu). `validate_crypto_address` yalnızca UI'da çağrılır; fonksiyon içinde derinlemesine savunma yoktur.

**Öneri:** `urllib.parse.quote(addr, safe="")` ile kodlayın ve fonksiyon içinde de regex doğrulaması yapın.

---

### V-18 — RAM zeroization iddiası (Bilgi, kısmi kanıt)

**Konum:** `military_vault.py:62-69`

**PoC kanıtı (PoC_15 — API sözleşme düzeyi):**
```
str  _zero_memory sonrasi icerik : 'S3cret-...'   (degismedi - str immutable)
[3] str nesnesinin ham bellek bolgesinde duz metin bulundu mu? True (offset ~40)
    Okunan veri: b'Gizli seed: witch collapse practi'
```

`_zero_memory` yalnızca `bytearray`'i sıfırlar; `str`/`bytes` için sessiz no-op'tur. `encrypt()` düz metnin 3 kopyasını üretir (str, immutable bytes, AESGCM dahili kopyası) ve yalnızca `password_bytes` bytearray'ini sıfırlar. `app.py:795-796` parola referansını `None` yapar ama string nesnesini silmez. (Not: Bu, gerçek forensic bellek dökümü kanıtı değil, API sözleşmesi kanıtıdır.)

**Öneri:** Kripto nesnelerini `mlock`/kilitli bellek + `cryptography` zeroize API'leri ile yönetin; iddiayı gerçeğe uygun revize edin.

---

### V-19 — Unicode profil adı: homoglif + sessiz dosya çakışması (Orta)

**Konum:** `vault_storage.py:208`

**PoC kanıtı (PoC_14):**
```
[1] get_profile_files('a.b') -> profiles/ab.mvat
    get_profile_files('ab')  -> profiles/ab.mvat | AYNI DOSYA MI? True
[!] Birinci kasanin parolasi artik CALISMIYOR: 'a.b' profili sessizce yok edildi!
[4] Homoglif: 'Аtlas' (Kiril A) vs 'Atlas' -> iki ayri ama gorsel olarak AYNI dosya
```

`str.isalnum()` Unicode harfleri kabul eder; noktalama ve diğer karakterler **silindiğinden** farklı adlar aynı dosyaya eşlenir. İkinci profil oluşturulunca birincinin kasası sessizce üzerine yazılır (doğrudan veri kaybı).

**Öneri:** `unicodedata.normalize("NFKD")` + ASCII whitelist; oluşturmadan önce hedef dosya varsa hata ver (çakışma reddi).

---

### V-20 — POST KDF testi üretim parametrelerini kapsamıyor (Orta)

**Konum:** `military_audit.py:58`

**PoC kanıtı (PoC_16):**
```
[1] POST sirasinda kullanilan scrypt parametreleri: [{'n': 1024, ...}]  (uretim: n=32768)
[2] 'Uretim parametrelerinde bozuk KDF' simule ediliyor: POST sonucu: all_passed = True
    Uretim yolu gercekten kirik: SIMULE: uretim parametrelerinde KDF bozuk!
```

POST, `n=1024` ile determinism testi yapar; üretim `log_n=15` (n=32768). Üretim parametreleriyle çalışan KDF bozuk olsa bile POST "%100 geçer" — boot assurance katmanı regresyonu yakalayamaz.

**Öneri:** Üretim parametreleriyle bilinen bir KAT vektörü doğrulayın; sınır değerlerini (`log_n=10/20`, `r=1/32`) de test edin.

---

### W-01 — ZK topic: offline parola doğrulayıcı + kaynakta sabit varsayılan anahtar (Yüksek)

**Konum:** `live_p2p_chat.py:42-49`, `app.py:71-73`

**PoC kanıtı (PoC_17):**
```
[1] Varsayilan topic (kaynak koddaki sabitlerden): aegisvault/v3/zk/26a3d72f57b658259deaaaf637a3
[3] Saldirgan (kaynak kodu okuyan herkes) mesaji cozdu: 'deadbeef:GercekKullanici: Gizli operasyon saati 21:00'
[3] Sonuc: bulundu='Kis732!!' | 17325. adayda | sure=46.8 ms | ~370,435 HMAC/sn (tek cekirdek CPU)
    Not: mesaj AES anahtari scrypt N=32768 ile korunuyor (~10^4/sn GPU cebri),
         ama TOPIC dogrulayicisi HMAC-SHA256 -> parola tahmini ~10^5 kat daha ucuz.
```

**Açıklama:** Topic `HMAC-SHA256(room_key, "AEGIS-ZK-ROOM-v3:"+room)` ile türetilir; HMAC anahtarı doğrudan `room_key`'dir ve **hiçbir yavaş KDF yoktur**. Broker/ag gözlemcisi (MQTT **TLS'siz port 1883**, `live_p2p_chat.py:22-23`) topic'i düz metin görür ve bu topic, `room_name` bilindiğinde bir **parola doğrulama oracle'ıdır**. Ayrıca `app.py:72-73`'te varsayılan oda/anahtar (`som-tim-01` / `AegisRoom2026!`) **kaynak kodda sabittir**; varsayılan kurulumda topic ve anahtar herkesçe bilinir — "E2E şifreli" varsayılan odalar şifresiz sayılır. Zayıf insan yapımı anahtarlar için mesaj şifrelemesindeki scrypt koruması devre dışı bırakılmış olur (topic ~10⁵ kat daha hızlı taranır).

**Öneri:** Topic türetiminde scrypt/Argon2id kullanın (aynı N=2^15 ile); varsayılan anahtarı kaldırın/zorunlu değiştirtin; MQTT'yi TLS 8883'e taşıyın.

---

### W-02 — Özel PQ-Hybrid KEM: CCA/FO yok, kapsül doğrulaması yok, sessiz anahtar sapması (Orta)

**Konum:** `crypto_utils.py:348-398` (`decapsulate`), `live_p2p_chat.py:164-177`

**PoC kanıtı (PoC_18):**
```
[A] v[0] += 123: decapsulate HATA VERMEDI. Anahtar degisti mi? True  (sessiz ayrisim)
[B] u[0] = 1e999: decapsulate HATA VERMEDI. Anahtar degisti mi? True
[C] u katsayilari negatif ve >= q: decapsulate HATA VERMEDI. Anahtar degisti mi? True
[D] Ayni bozuk kapsul HER ZAMAN ayni anahtari uretir: True
[E] Kaynak: tek dogrulama `if len(u_poly) != LWE_N ...` — katsayi aralik/tip kontrolu YOK
```

**Açıklama:** FIPS 203 (ML-KEM) uyumlu bir KEM'de kapsül doğrulanır ve çözme hatası **implicit rejection** ile sahte-rastgele anahtara gider; ayrıca FO dönüşümü kapsülü anahtara bağlar. Bu uygulamada katsayılar (negatif, ≥q, `inf`, hatta string olmayan tipler) doğrulanmaz; tek katsayılık MITM değişikliği anahtarı **hata vermeden** değiştirir ve aynı bozuk kapsül her zaman aynı anahtarı üretir. Protokolde key confirmation olmadığından taraflar sessizce desenkronize olur (DoS) ve "kapsül bütünlüğü" iddiası kriptografik olarak boştur. (Not: Python'un 4300-basamak tamsayı dönüşüm limiti, huge-int CPU DoS varyantını doğal olarak sınırlar; bu nedenle bu raporda DoS iddiası yapılmamıştır.)

**Öneri:** Standart ML-KEM (liboqs / OpenSSL 3.5+ / `cryptography`'nin ML-KEM desteği) kullanın. Ara çözüm olarak: katsayı aralık/tip doğrulaması + `m = G(m' ‖ H(ct ‖ pk))` tarzı FO dönüşümü + key confirmation (ratchet sonrası bir doğrulama mesajı) ekleyin.

---

## 3. PoC Paketi

| PoC | Bulgu | Sonuç |
|-----|-------|-------|
| `security_audit/PoC_01_security_state_tamper.py` | V-01, V-02, V-03, V-09 | ✅ Kanıtlandı |
| `security_audit/PoC_02_audit_trail_rewrite.py` | V-05 | ✅ Kanıtlandı |
| `security_audit/PoC_03_pqkem_handshake_hijack.py` | V-04 | ✅ Kanıtlandı |
| `security_audit/PoC_04_zeroize_path_traversal.py` | V-06 | ✅ Kanıtlandı |
| `security_audit/PoC_05_duress_timing_sidechannel.py` | V-07 | ✅ Kanıtlandı |
| `security_audit/PoC_06_zeroize_false_attestation.py` | V-08 | ✅ Kanıtlandı |
| `security_audit/PoC_07_post_not_enforced.py` | V-11 | ✅ Kanıtlandı |
| `security_audit/PoC_08_backdoor_shield_bypass.py` | V-12 | ✅ Kanıtlandı |
| `security_audit/PoC_09_updater_unsigned_binary.py` | V-10 | ✅ Kanıtlandı |
| `security_audit/PoC_10_hw_fingerprint_and_decoy.py` | V-13, V-14 | ✅ Kanıtlandı |
| `security_audit/PoC_11_p2p_sender_spoof_and_replay.py` | V-15 | ✅ Kanıtlandı |
| `security_audit/PoC_12_message_replay_stego.py` | V-16 | ✅ Kanıtlandı |
| `security_audit/PoC_13_portfolio_url_injection.py` | V-17 | ✅ Kanıtlandı |
| `security_audit/PoC_14_unicode_profile_collision.py` | V-19 | ✅ Kanıtlandı |
| `security_audit/PoC_15_ram_zeroization_gap.py` | V-18 | ✅ Kısmi (API sözleşmesi) |
| `security_audit/PoC_16_post_kdf_coverage.py` | V-20 | ✅ Kanıtlandı |
| `security_audit/PoC_17_zk_topic_dictionary.py` | W-01 | ✅ Kanıtlandı |
| `security_audit/PoC_18_pqkem_malleability.py` | W-02 | ✅ Kanıtlandı |

**Çalıştırma:**
```bash
./security_audit/run_all.sh          # tüm PoC'lar + log
python3 security_audit/PoC_01_security_state_tamper.py   # tekil
```

PoC'lar `/tmp/opencode/aegis_poc/` altında izole sandbox dizinlerinde çalışır; proje dosyalarını değiştirmez.

---

## 4. Öncelikli Düzeltme Sırası

1. **V-02/V-03/V-09** — `vault_storage` sayaç ve state bütünlüğü (fail-closed + profil izolasyonu + gerçek gizli HMAC anahtarı)
2. **V-04** — PQ-KEM handshake kimlik bağlama (transcript imzası + tek-ACK politikası)
3. **V-05/V-08** — Audit zinciri imzalama + zeroize doğrulama/sahte rapor düzeltmesi
4. **V-06** — Yol sanitizasyonu (tek ortak fonksiyon)
5. **V-07** — Sabit-zamanlı unlock (duress deniability)
6. **V-10** — Updater hash/imza zorunluluğu
7. **V-11/V-12** — POST fail-closed + gerçek kod bütünlüğü
8. **V-13/V-14** — Donanım kök güveni + decoy dosya düzeni
9. **W-01** — Topic KDF'i (scrypt/Argon2) + varsayılan anahtarın kaldırılması + MQTT TLS
10. **W-02** — PQ-KEM'i standart ML-KEM'e geçirme (veya FO + katsayı doğrulaması + key confirmation)
11. Kalan düşük bulgular

---

## 5. Notlar ve Kapsam

- Bu denetim, projenin README'sinde iddia edilen güvenlik özelliklerinin **doğrulanmasına** odaklanmıştır; iddiaların bir kısmı (AAD bağlama, scrypt OOM sınırları, SSS doğruluğu, nonce üretimi) doğru çıkmıştır.
- Kripto ilkellerinin (libsodium/cryptography) kendisi denetlenmemiştir; PoC'lar uygulama katmanı mantık hatalarını hedefler.
- `PQHybridKEM`'in matematiksel güvenliği (ternary Ring-LWE, n=256, q=3329) bağımsız kriptoanaliz gerektirir; bu raporda **protokol** zafiyetleri kanıtlanmıştır (V-04 ele geçirme, W-02 kapsül bütünlüğü/CCA eksikliği), primitifin kendisi kapsam dışıdır. Unutulmamalıdır ki bu şema ML-KEM/FIPS 203 değildir ve "FIPS 203 inspired" ifadesi uyumluluk anlamına gelmez.
- `.exe` ikilisi (80 MB PyInstaller) kaynakla eşleştiği varsayılmıştır; ikili-seviye denetim (strings/imha analizi) yapılmamıştır.

---

## 6. PoC Doğrulama Denetimi (metodoloji)

Tüm PoC'lar yanlış-pozitif riskine karşı denetlendi: hedef kod birebir okundu, stub/spy'lerin sadakati ve monkeypatch'lerin üretim davranışını değiştirip değiştirmediği kontrol edildi.

| PoC | Yöntem | Sadakat | Not / Olası yanılgı |
|-----|--------|---------|---------------------|
| 01 | Gerçek `MilitaryVault`/`vault_storage` API; HMAC yeniden hesaplama | Sadık | HMAC anahtarının açık türetimi `vault_storage.py:36,79-80` ile doğrulandı |
| 02 | Gerçek audit zinciri; saldırgan kendi hash'lerini yazıyor | Sadık | Zincir tasarımı gereği anahtarsız olduğundan "saldırgan hesaplayabilir" gerçekçi |
| 03 | paho stub (yalnız publish yakalar) + gerçek `_on_mqtt_message` | Sadık | Ağ katmanı stub; şifreleme/ratchet akışı gerçek kod |
| 04 | Gerçek `emergency_zeroize_vault` | Sadık | Erişilebilirlik kanıtlandı: `app.py:400` kullanıcı girdisi → `app.py:2230` panic-zeroize |
| 05 | Gerçek `unlock_vault`, 3 örneklem ortalaması | Sadık (etki ~2.9x) | Metodolojik not: medyan + N≥10 ile güçlendirilebilir; etki büyüklüğü eşiğin çok üzerinde |
| 06 | Gerçek fonksiyon; `chmod` ile IO hatası enjeksiyonu | Sadık | [B] farklı-CWD senaryosu; [A] (salt-okunur/IO hatası) asıl gerçekçi yol |
| 07 | `app.py:78-81` birebir replike + gerçek POST | Sadık | Koşulsuz kayıt kaynaktan doğrulandı (`app.py:79-81`) |
| 08 | Modül kopyalarında gerçek shield; `__file__` kasıtlı yönlendirildi | Sadık | Supply-chain senaryosu; fidye yazılımı gibi diğer senaryolar kapsam dışı |
| 09 | `urlopen`/`Popen`/`sys.exit` stub; gerçek doğrulama mantığı çalıştı | Sadık | `app.py:813`'te hash'siz çağrı kaynaktan doğrulandı |
| 10 | `platform.node` patch + gerçek vault akışı | Sadık | Donanım simülasyonu değil değer spoof'u; zafiyet zaten "değerler açık" önkabulüne dayanır |
| 11 | paho stub + gerçek `_on_mqtt_message`; restart = yeni oturum/boş nonce cache | Sadık | Replay penceresi ±600 sn (`live_p2p_chat.py:125`) |
| 12 | Gerçek `crypto_chat`/`steganography` API | Sadık | — |
| 13 | `urlopen` spy + kaynak kanıtı | Sadık | Etki sınıfı "yol manipülasyonu" (SSRF değil) olarak etiketlendi |
| 14 | Gerçek `init_vault`/`unlock_vault` | Sadık | Veri kaybı (üzerine yazma) canlı gözlemlendi |
| 15 | Süreç-içi bellek okuma (`id` + `string_at`) | Kısmi | Forensic dump değil; raporda "kısmi/API sözleşmesi" olarak etiketli |
| 16 | Scrypt delegasyonlu spy + gerçek POST | Sadık | `cryptography` C tipi subclass edilemediğinden sarmalayıcı kullanıldı |
| 17 | Gerçek HMAC formülü + kaynaktaki varsayılanlar (`app.py:72-73`) | Sadık | Hız tek-çekirdek ölçümü; GPU tahmini büyüklük mertebesi |
| 18 | Gerçek `PQHybridKEM` API | Sadık | Big-int DoS varyantı Python tamsayı limiti nedeniyle iddia edilmedi |

**Genel değerlendirme:** 16/18 PoC "gerçek kod yolu" test ediyor; 2'si (15: süreç-içi bellek, 16: delegasyon spy) yöntemsel olarak sınırlı ve raporda açıkça etiketli. Ağ katmanı gerektiren testlerde (03, 11, 17) `paho` stub'ı yalnızca taşıma katmanını taklit eder; kripto/protokol akışı proje kodundan değiştirilmeden çalışır. Stub'ların gerçek paho davranışından sapması bulguları etkilemez (bulgular mesaj içeriği/kimlik doğrulama katmanındadır).

---

## 7. Kriptografik Derin Analiz Notları

**Doğru/iyi uygulanmış (kanıtlanan):**
- AES-256-GCM: 96-bit rastgele nonce, 128-bit rastgele salt, header (magic/version/KDF/parametreler/salt/nonce) AAD'ye bağlı; bit-flip AEAD tarafından reddediliyor; hata mesajları birleşik (parola/tamper ayrımı sızdırmıyor).
- scrypt: N=2^15, r=8, p=1 üretim; decrypt tarafında ön-doğrulama (`log_n 10..20`, RAM 512 MB cap, p≤16) ile OOM DoS sınırlandırılmış; salt CSPRNG.
- Shamir GF(257): reddetme örneklemesi ile byte-güvenli; Lagrange interpolasyonu doğru; eşik altı paylaşımların dağılımı sır baytından bağımsız (koşullama analizi ile kontrol edildi).
- CSPRNG kullanımı tutarlı: `os.urandom`, `secrets.choice/token_hex/randbelow`.
- BIP-39 doğrulayıcı yalnızca format/uzunluk kontrolü yapar (checksum doğrulaması yok) — bilgi notu; kasa güvenliğini etkilemez ama yanlış yazılmış seed'lerin "geçerli" görünmesine yol açar.

**Zayıf/yeniden tasarlanması gereken (W-01/W-02 ile ilişkili):**
- Özel Ring-LWE KEM: NTT yok (schoolbook O(n²) — performans), standart KEM'lerdeki katsayı sıkıştırma/decompress ve FO dönüşümü yok, katsayı doğrulaması yok, anahtar onayı yok; kombiner `HKDF(z‖m, salt=SHA3(epk‖u‖v))` makul ama bağımsız analiz edilmemiş özel tasarım. "ML-KEM/FIPS 203" iddiaları uyumluluk değil ilham düzeyindedir (W-02).
- Topic türetimi: HMAC ile hızlı doğrulayıcı (W-01); varsayılan anahtar kaynakta sabit.
- `password + "|HW:" + hw + "|KF:" + kf` birleştirmesi ayraç-kaçışsız düz string; domain separation yerine string concat (pratik istismar düşük, tasarım kokusu).
- Steganografi "ayırt edilemezlik" iddiası zayıf: `AGSTEG` sabiti bit 0'dan itibaren sıralı LSB'lere gömülür (`steganography.py:17,49,71-72`) → chi-square/RS steganalizi ve bilinen-magic taraması ile kolayca tespit edilir; passkey verilmezse içerik şifresiz gömülür (kullanıcı "gizli" sanabilir).
- MQTT 1883 (TLS yok): topic ve zamanlama metadata'sı ağda açık; W-01 sözlük saldırısını sahada uygulanabilir kılar.
- `decrypt` header'daki scrypt parametrelerini kabul ettiğinden, saldırgan 512 MB/çağrı sınırında CPU-yoğun kasa üretip istemciyi yavaşlatabilir (sınırlı DoS; hardening notu).

---

## 8. Mimari Değerlendirme (denetçi notu)

> Bu bölüm, bulguların ötesinde ürünün genel mimarisine ilişkin denetçi görüşüdür; düzeltme kapsamı planlanırken yol haritası olarak kullanılabilir.

**Ürün amacı (anlaşıldığı haliyle):** Windows masaüstü, "askeri sınıf" iddialı, kripto seed/parola kasası + gizli iletişim (P2P / stego / QR) + duress/DMS gibi baskı-altı senaryolarını hedefleyen sivil güvenlik ürünü.

**Hüküm:** Yerel kasa zarfı (`military_vault.py`: AES-256-GCM + scrypt + AAD'li versiyonlu header + sınırlı parametreler) mimari olarak makuldür. Ancak **ürün mimarisi, iddia ettiği güvenlik modeliyle tutarsızdır**; bu tek tek bug'ların değil, birkaç yapısal kararın sonucudur.

**Yapısal sorunlar:**

1. **Güven sınırı yanlış katmanda.** Rate-limit / Scorched-Earth / DMS politika olarak GUI katmanında (`vault_storage.unlock_vault`), kasa dosyası ise kendi kendine yeterli (V-01). Offline saldırgan bu katmana hiç girmez. Anti-brute-force'un doğası "her tahmini pahalı yapmak"tır; sayaç/state dosyası mimari olarak offline savunma değildir. Duress/DMS birer **ürün özelliği** olarak konumlanmalı, güvenlik sınırı olarak değil.

2. **Kök güven ve anahtar hiyerarşisi yok.** Parola doğrudan veri anahtarını türetir; HW binding ve keyfile yalnızca string birleştirmedir (`p|HW:..|KF:..`). KEK/DEK ayrımı, TPM/DPAPI gibi donanım kökü, ayrı faktör katmanı yok. Doğrudan sonuçları: aday-parola döngüleri ve timing oracle (V-07), sahte donanım bağlama (V-13). Doğru desen: rastgele DEK'in çoklu "unlock slot" ile sarılması; her açma yolunun tek ve sabit maliyetli olması.

3. **Güvence (assurance) bileşenleri "security theater".** Anahtarsız, yeniden hesaplanabilir audit zinciri (V-05); uygulanmayan POST + koşulsuz "100% Passed" kaydı (V-11); özeti hiçbir yerde doğrulanmayan "shield" (V-12); sahte zeroization raporu (V-06/V-08); imzasız self-updater (V-10). Assurance, saldırganın taklit edemeyeceği, birbirine bağlı bir zincir olmalıdır — burada bağımsız rozetlerden oluşur.

4. **İletişim katmanı ad hoc protokol + özel kripto.** Sıfırdan Ring-LWE (FO yok, doğrulama yok — W-02); kimlik katmanı olmayan grup anahtarı ve HMAC topic (W-01, varsayılan anahtar kaynakta sabit); TLS'siz MQTT 1883; key confirmation / ratchet yok (V-04, V-15). Bu katman Noise/Signal benzeri bir protokol + standart ML-KEM ile yeniden yazılmalı; MQTT yalnızca taşıma olarak kalmalıdır.

5. **Bileşen sınırları ve durum yönetimi.** Global mutable state (`_failed_attempts` → V-03), CWD'ye göre çözülen dosya yolları (V-08), tüm verinin tek blob olarak RAM'e inmesi. "Çekirdek kütüphane (politika + saf nesneler) ve ince GUI" ayrımı yok; mimari hataların çoğu bu sınırdan sızıyor.

**Mimari olarak doğru olanlar:** zarf formatı/versiyonlama ve AAD bağlama; scrypt parametreleri ve ön-doğrulama sınırları; atomik yazma deseni; CSPRNG kullanımı; SSS matematiği. Çekirdek kasa sağlam; sorun çekirdeğin etrafındaki modelde.

**Yeniden mimari yol haritası (bu sırayla):**
1. Tehdit modelini yazılı hale getirin ve iddiaları buna göre küçültün ("military-grade" yerine somut saldırgan profilleri).
2. KEK/DEK + donanım destekli kök (TPM/DPAPI) + tek-maliyetli çoklu unlock slot.
3. Deniability'yi tek dosya / opak slot tasarımına taşıyın (ayrı `_decoy.mvat` değil).
4. İletişimi standart protokole (Noise/Signal-tarzı, ML-KEM) ve TLS'li taşımaya geçirin.
5. İmzalı güncelleme + gerçek (anahtarlı/uzak çapalı) integrity anchoring.
6. Uygulama veri dizini + katmanlı paket yapısı (core / protocol / ui).

**Özet:** İyi bir "demo ürünü" mimarisi; iddia edilen güvenlik modeliyle uyumlu bir mimari değil. Yerel kasa hedefli düzeltmelerle taşınabilir; P2P / duress / assurance tarafı mimari olarak yeniden çizilmelidir.

---

## 9. PR'a Taşınacak Somut Katkılar

Bu denetimin çıktıları PR serisi olarak şu paketlerde taşınabilir:

| # | Katkı | İçerik | Dosya / Kanıt | Önerilen PR |
|---|-------|--------|---------------|-------------|
| K-01 | Çalıştırılabilir PoC paketi | 22 bulgunun tamamı için 18 PoC + `run_all.sh` (izole sandbox, proje dosyalarına dokunmaz) | `security_audit/PoC_*.py`, `run_all.sh` | PR-1: denetim paketi |
| K-02 | PoC doğrulama denetimi | 18 PoC'nin yanlış-pozitif analizi; kısmi kanıtların (15/16) açıkça etiketlenmesi | Bu rapor §6 | PR-1 |
| K-03 | Kripto derin analiz | İyi/kötü ayrımı + 2 yeni bulgu (W-01, W-02) | Bu rapor §7, PoC_17/18 | PR-1 + PR-3 girdisi |
| K-04 | Öncelikli düzeltme planı | 11 maddelik sıralı yol haritası, her madde bulgu+konum referanslı | Bu rapor §4 | PR-2/PR-3 yol haritası |
| K-05 | Mimari değerlendirme | 5 yapısal sorun + 6 adımlı yeniden mimari önerisi | Bu rapor §8 | PR-4: mimari RFC |
| K-06 | Teknoloji seçim analizi | Bileşen bazında dil/stack önerisi ve gerekçe | Bu rapor §10 | PR-4: mimari RFC |
| K-07 | Düzeltme PR'larına hazır bulgular | Her bulgu için dosya:satır + öneri + PoC regresyon testi | §2, §4, `run_all.sh` | PR-2/PR-3 |

**Önerilen PR serisi:** PR-1 denetim paketi (yalnız `security_audit/`, üretim kodu değişmez) → PR-2 kritik mantık düzeltmeleri (V-02/V-03/V-06/V-09/V-10) → PR-3 kripto/protokol (W-01/W-02/V-04/V-15) → PR-4 mimari RFC (Rust çekirdek + teknoloji geçişi). Her düzeltme PR'ında ilgili PoC "fail→pass" regresyon testi olarak bağlanabilir.

---

## 10. Mimari & Teknoloji Seçimi Öneri Tablosu

| Bileşen | Mevcut Durum | Ana Sorun | Önerilen Mimari | Önerilen Teknoloji | Öncelik |
|---------|--------------|-----------|-----------------|--------------------|---------|
| Kasa çekirdeği (zarf/KDF) | Python `military_vault.py` | Sır sıfırlama garantisi yok (V-18); primitive timing | Rastgele DEK + KEK sarma, zeroize, sabit-zamanlı API | **Rust**: `aes-gcm`, `argon2`/`scrypt`, `zeroize`, `subtle`, `secrecy` | P0 |
| Anahtar kökü / HW binding | hostname+mimari fingerprint (V-13) | Kamuya açık sahte kök güven | DEK'i donanım köküyle sarma (TPM/DPAPI), keyfile ayrı faktör | **Rust**: `tss-esapi`, `windows-rs` (DPAPI) | P0 |
| PQ-KEM | Elle yazılmış Ring-LWE (W-02) | FO/CCA yok, doğrulama yok, doğrulanmamış primitif | Standart ML-KEM + kimlik bağlı el sıkışma | **Rust**: `libcrux-ml-kem` / `pqcrypto`; alternatif **Go**: CIRCL | P0 |
| Updater | İmzasız `.exe` (V-10) | RCE / supply-chain | İmza zorunlu, hash pinleme, reproducible build | **Rust/Go** CLI + `minisign`/Ed25519; Windows kod imzalama | P0 |
| P2P protokol & taşıma | Kimliksiz grup anahtarı, MQTT 1883 (V-04/V-15/W-01) | Kimlik yok, forward secrecy yok, topic parola oracle'ı | Ed25519 kimlik + X3DH/çift ratchet (Noise/Signal deseni), TLS taşıma | **Go** (networking) veya **Rust** (`snow`); TLS 8883 | P1 |
| Deniability (duress/decoy) | Ayrı `_decoy.mvat`, timing (V-07/V-14) | Yapısal olarak ifşa | Tek dosya/opak slot; sabit maliyetli unlock (tüm slotlar denenir) | Rust çekirdek (slot tasarımı) | P1 |
| Audit trail | Anahtarsız hash zinciri (V-05) | Yeniden yazılabilir, silinebilir | Anahtarlı zincir (HMAC) veya uzak çapa; append-only | Rust çekirdek + OS korumalı anahtar | P1 |
| Assurance (POST/shield) | Kozmetik rozet (V-11/V-12) | Uygulanmıyor, doğrulanmıyor | Fail-closed açılış; imzalı build + KAT'lar üretim parametreleriyle | Rust build pipeline (reproducible + `cosign`/`minisign`) | P2 |
| Steganografi / QR | Python | "Gizli" iddiası tespit edilebilir | Tespit-dirençli gömme VEYA iddianın "şifreli taşıma" olarak düzeltilmesi | Python yeterli (güvenlik-kritik değil) | P3 |
| SSS / BIP-39 | Python, checksum eksik | Vetted olmayan yardımcı kod | Standart kütüphaneler | **Rust**: `vsss-rs`, `bip39` | P3 |
| GUI | Python CustomTkinter | Çekirdeğe doğrudan erişim | İnce istemci; gizli anahtar GUI sürecine hiç girmez | Kısa vade: Python + **PyO3** köprü; orta vade: **Tauri/egui** | P2 |
| Denetim/PoC altyapısı | Python | — | Regresyon test paketi olarak korunmalı | Python (`security_audit/`) | — |

**Geçiş stratejisi (özet):** Önce mimariyi düzelt (PR-4 RFC), sonra çekirdeği Rust'ta yazıp PyO3 ile mevcut GUI'ye bağla; GUI ve stego Python'da kalabilir. Go yalnızca ağ/servis katmanı için değerlendirilmelidir; sır işleyen çekirdekte Rust'ın zeroization/constant-time avantajı Go'da yoktur (GC). Dil değişikliği tek başına bulguların ~%80'ini çözmez — tablodaki P0/P1 mimari kararlar, dilden bağımsız olarak önce uygulanmalıdır.
