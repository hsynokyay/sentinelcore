# SentinelCore SAST Engine — 12 Haftalık Geliştirme Roadmap'i

> **Bu doküman Claude Code (VS Code terminal) için yazılmıştır.**
> Her faz bağımsız olarak çalıştırılabilir. Sıralı ilerlemek önerilir, ama paralelize edilebilir görevler işaretlidir.

---

## 0. Bağlam (Context)

### Mevcut Mimari (Baseline)

SentinelCore zaten çalışan bir SAST motorudur. Sıfırdan yazma **YOKTUR**. Tüm değişiklikler mevcut kod tabanına eklenir.

**Mevcut yetenekler:**
- 99 aktif rule (sast-worker startup log: `"rules":99`)
- 4 dil için kendi yazılmış lexer + parser + IR (Java/Python/JavaScript/C# — el yazımı pure-Go, harici parser dependency yok)
- AST → IR → Callgraph → Interprocedural taint analizi
- Secrets için ayrı regex matcher
- Production'da çalışıyor: Boyner deployment + cross-function taint testleri geçiyor

**Java parser'ın kapsadığı alt-küme:**
- `internal/sast/frontend/java/lexer.go` — 371 satır hand-rolled tokenizer
- `internal/sast/frontend/java/parser.go` — 1552 satır single-pass + brace-depth parser
- `internal/sast/frontend/java/frontend.go` — 57 satır file walker
- Package + import (static + wildcard), class/interface/enum (nested dahil), method decl (parameter modeli yok), method invocation + receiver chain, string literal args
- Tests: ~730 satır

**Test artifact'ı (regression suite):**
- `vulnerable-java-app.zip` — 14 dosya, ~100+ pattern (kullanıcı tarafından sağlandı)
- Mevcut scan sonucu: 62 finding raporlanıyor ama ~12 gerçek bulgu (dedup eksikliği)

### Tespit Edilen Açıklar (Mayıs 2026 vulnerable-java-app scan'inden)

**Kritik problemler:**
1. **Dedup yok** — aynı `(file, line, vuln_class)` 4 kez raporlanıyor (Java/Python/JavaScript/C# secret kuralları hepsi aynı `.java` dosyasına çalışıyor)
2. **Dil-uzantı router yok** — `.java` dosyasına `SC-PY-SECRET-001` ve `SC-CSHARP-SECRET-001` çalışıyor
3. **JSP/XML/properties/pom.xml dosyaları taranmıyor** — coverage gap
4. **SCA yok** — pom.xml'deki Log4Shell, Spring4Shell, Struts2 vb. 15+ CVE kaçırıldı
5. **Rapor kalite sorunları** — yarım kalmış cümleler ("How to fix: ... 1."), tutarsız tip etiketleri

**Coverage boşlukları (yakalanması gereken pattern'ler):**

| Kategori | Eksik Sink/Pattern |
|---|---|
| Crypto | `MessageDigest.getInstance("MD5"\|"SHA-1")`, `Cipher.getInstance("DES"\|"RC4"\|"Blowfish"\|"AES/ECB/...")`, static IV (`new IvParameterSpec(new byte[16])`), 512-bit RSA, `TrustManager` accept-all, `HostnameVerifier` accept-all |
| SQL | `Statement.executeQuery(concat)`, misused `PreparedStatement`, `String.format` SQL |
| Command | `Runtime.exec(concat)`, `ProcessBuilder` ile shell concat |
| Path Traversal | `new File(concat)`, `new FileInputStream(concat)`, Zip Slip (`ZipEntry.getName()` validation eksikliği) |
| XXE | `DocumentBuilderFactory` external entity disable kontrolü, `SAXParserFactory`, `XMLReader` |
| SSRF | `URL.openConnection`, `HttpURLConnection.connect`, Apache `HttpClient.execute` |
| XSS | `PrintWriter.println(userInput)`, `response.getWriter().write(taint)` |
| Open Redirect | `response.sendRedirect(userInput)` |
| Deserialization | Jackson `enableDefaultTyping`, XStream `fromXML`, SnakeYAML `Yaml.load` |
| Spring | `SpelExpressionParser.parseExpression`, `ScriptEngine.eval`, `Class.forName(taint)` + reflection |
| Auth/Session | `Cookie.setSecure(false)`, `setHttpOnly(false)`, missing session regenerate, LDAP injection (`InitialDirContext.search` concat) |
| JSP scriptlet | `<%= %>` ile reflected XSS, scriptlet içinde tüm Java sink'ler |
| Config | `web.xml` security-constraint eksikliği, `application.properties` plaintext secret |

### Hedef Çıktı

12 hafta sonunda:
- **150+ kural** (99 → 150+) — Semgrep'in core Java rule sayısının ~%70'i
- **Dedup + severity policy** ile gerçek finding sayısı = raporlanan finding sayısı
- **JSP, XML, properties, pom.xml** tarama desteği
- **SCA modülü** — OSV.dev API ile dependency CVE eşlemesi
- **SARIF 2.1.0 export** — GitLab/SonarQube/DefectDojo entegrasyonu için
- **VS Code extension MVP** — IDE'de inline finding gösterimi
- **Regression test suite** — her release'de coverage % otomatik raporu

---

## 1. Sprint Yapısı ve Görev Formatı

Plan **6 sprint × 2 hafta** = 12 hafta olarak yapılandırılmıştır.

Her sprint:
- **Hedef:** Sprint sonunda yapılmış olması gereken net çıktı
- **Görevler:** Atomik, test edilebilir, dosya path'i belirtilmiş
- **Kabul kriterleri:** Hangi test geçince "done" sayılır
- **Bağımlılıklar:** Hangi önceki sprint'in çıktısına bağlı

Görevlerde bu konvansiyon kullanılmıştır:
- `[CC]` = Claude Code'a verilebilir, autonomous yapılabilir görev
- `[H]` = Human input gerekir (mimari karar, code review, infra)
- `[CC+H]` = Claude Code başlar, insan validate eder

---

## SPRINT 1 — Temizlik ve Hijyen (Hafta 1-2)

> **Amaç:** Mevcut 62 finding'lik raporu 12 gerçek finding'e indir. Coverage artmadan önce gürültüyü kes.

### 1.1 Dil-Uzantı Router (Critical)

**Sorun:** `.java` dosyasına `SC-PY-SECRET-001`, `SC-JS-SECRET-001`, `SC-CSHARP-SECRET-001` kuralları çalışıyor.

**Görevler:**
- [CC] `internal/sast/engine/router.go` oluştur
- [CC] Her rule'a `target_languages: []string` field ekle (rule metadata struct'ında)
- [CC] Mevcut 99 kuralın metadata'sını güncelle: `SC-JAVA-*` → `["java"]`, `SC-PY-*` → `["python"]` vb.
- [CC] Engine'in rule dispatch loop'unda dosya extension → language mapping kontrolü ekle (`.java`→java, `.py`→python, `.js/.ts/.jsx/.tsx`→javascript, `.cs`→csharp)
- [CC] Her rule sadece kendi dil hedefindeki dosyalara çalışsın

**Kabul kriteri:**
```bash
# Önce
$ ./sast-worker scan vulnerable-java-app.zip | jq '.findings | length'
62
# Sonra
$ ./sast-worker scan vulnerable-java-app.zip | jq '.findings | length'
≤20
```

### 1.2 Dedup Layer

**Sorun:** Aynı `(file, line, rule_id)` veya `(file, line, vuln_class)` birden fazla raporlanıyor.

**Görevler:**
- [CC] `internal/sast/engine/dedup.go` — `Finding`'ler için canonical key fonksiyonu (`file:line:vuln_class` veya `file:line:rule_family`)
- [CC] Rule family kavramı: `SC-JAVA-SECRET-001` ve `SC-PY-SECRET-001` aynı `vuln_class: HARDCODED_SECRET` 'e sahip olmalı (rule metadata'sında `vuln_class` field'ı ekle)
- [CC] Engine sonunda dedup pass: aynı canonical key'e sahip finding'lerden en yüksek severity olanı bırak, diğerlerini sup
- [CC] Dedup edilen finding sayısını rapor metadata'sına `findings_deduplicated: N` olarak yaz

**Kabul kriteri:**
- Tek `Secrets.java:49` için 4 finding → 1 finding
- Rapor metadata'sında dedup sayısı görünür

### 1.3 Severity Policy Dosyası

**Sorun:** SQLi olsaydı High mı Critical mi belirsiz, severity tutarsız.

**Görevler:**
- [CC] `internal/sast/severity/policy.yaml` oluştur:
  ```yaml
  vuln_classes:
    SQL_INJECTION: critical
    COMMAND_INJECTION: critical
    UNSAFE_DESERIALIZATION: critical
    XXE: critical
    SSRF: high
    PATH_TRAVERSAL: high
    HARDCODED_SECRET: high
    WEAK_CRYPTO: high
    INSECURE_RANDOM: high
    XSS_REFLECTED: high
    XSS_STORED: high
    OPEN_REDIRECT: medium
    LDAP_INJECTION: high
    LOG_INJECTION: medium
    INSECURE_COOKIE: medium
    MISSING_CSRF: medium
    INFO_DISCLOSURE: low
    CODE_QUALITY: info
  ```
- [CC] Her rule metadata'sında `vuln_class` zorunlu olsun
- [CC] Engine policy.yaml'dan severity okusun, rule'da hardcoded olmasın

**Kabul kriteri:**
- Rule severity değişikliği için kod değişikliği değil yaml değişikliği yeter
- Tüm 99 rule'da `vuln_class` set edilmiş

### 1.4 Rapor Şablonu Düzeltmeleri

**Görevler:**
- [CC] `internal/sast/report/templates/markdown.tmpl` (veya muadili) içindeki "How to fix: ... 1." yarım kalmış cümleyi düzelt
- [CC] Java dosyasında "in C# source code" gibi cross-language metin akışını fix'le (router 1.1'den sonra zaten olmamalı, ama template'de güvenlik kontrolü)
- [CC] DAST findings ayrı bir bölüme alınsın, SAST raporu sadece SAST içersin (mevcut karışım hatası)

### 1.5 Regression Test Harness

**Görevler:**
- [CC] `tests/regression/` klasörü oluştur
- [CC] `vulnerable-java-app.zip` test corpus olarak ekle
- [CC] `tests/regression/expected/vulnerable-java-app.json` — beklenen finding'ler (file, line, vuln_class) listesi
- [CC] `make regression-test` hedefi: scan çalıştırır, expected ile karşılaştırır, **coverage %** raporu basar
- [CC] CI'a entegre et (eğer GitHub Actions/GitLab CI varsa)

**Kabul kriteri:**
- `make regression-test` çalışır ve şöyle çıktı verir:
  ```
  Expected findings: 87
  Detected: 12 (13.8%)
  False positives: 2
  False negatives: 75
  ```

**Sprint 1 Çıkış Kriteri:** vulnerable-java-app raporu 12-15 unique finding gösteriyor, severity tutarlı, coverage % baseline'ı kayda geçti.

---

## SPRINT 2 — Crypto + Secret Pattern Genişletme (Hafta 3-4)

> **Amaç:** Pattern matching ile yakalanabilen "kolay meyveler"i topla. Taint engine'e dokunma, sadece AST node match.

### 2.1 Java Crypto Rules

Aşağıdaki kuralları yaz. Her biri AST-based MethodInvocation match'i + string literal arg kontrolü:

**Görevler:**
- [CC] `SC-JAVA-CRYPTO-WEAK-HASH` — `MessageDigest.getInstance("MD5"|"SHA-1"|"SHA1"|"MD2"|"MD4")` (CWE-327)
- [CC] `SC-JAVA-CRYPTO-WEAK-CIPHER` — `Cipher.getInstance("DES"|"3DES"|"DESede"|"RC4"|"ARCFOUR"|"Blowfish"|"RC2")` (CWE-327)
- [CC] `SC-JAVA-CRYPTO-ECB-MODE` — `Cipher.getInstance` arg'ında `/ECB/` substring (CWE-327)
- [CC] `SC-JAVA-CRYPTO-STATIC-IV` — `new IvParameterSpec(new byte[N])` veya `new IvParameterSpec("literal".getBytes())` (CWE-329)
- [CC] `SC-JAVA-CRYPTO-WEAK-RSA` — `KeyPairGenerator.initialize(N)` N < 2048 (CWE-326)
- [CC] `SC-JAVA-CRYPTO-WEAK-DH` — `DHParameterSpec` ile P değeri < 2048 bit
- [CC] `SC-JAVA-CRYPTO-UNSALTED-HASH` — `MessageDigest.update()` veya `digest()` çağrısı, aynı method body'sinde salt yok (basit heuristic, false positive olabilir, severity=Medium)
- [CC] `SC-JAVA-SSL-TRUST-ALL` — Bir class veya anonymous class `X509TrustManager` implement ediyor ve `checkServerTrusted` boş (return; veya hiçbir throw yok) (CWE-295)
- [CC] `SC-JAVA-SSL-HOSTNAME-VERIFIER` — `HostnameVerifier` implement edilen yerlerde `verify` her zaman `true` döner (CWE-297)
- [CC] `SC-JAVA-SSL-CONTEXT-WEAK` — `SSLContext.getInstance("SSL"|"SSLv2"|"SSLv3"|"TLSv1"|"TLSv1.1")` (CWE-326)

**Test:**
- [CC] Her kural için `tests/rules/java/crypto/<rule_id>_test.go` oluştur
- [CC] Pozitif + negatif test case'ler (true positive + true negative)
- [CC] vulnerable-java-app'te beklenen finding'lere ekle: `expected/vulnerable-java-app.json` güncelle

### 2.2 Secret Detection — False Positive Azaltma + Yeni Pattern'ler

**Sorun:** Şu anki secret regex'i "MySecretKey12345" gibi placeholder'ları yakalıyor (test verisinde bu OK ama production'da gürültü).

**Görevler:**
- [CC] `internal/sast/secrets/patterns.yaml` — yeni pattern'ler ekle:
  - GitHub fine-grained PAT (`github_pat_[A-Za-z0-9_]{82}`)
  - GitLab PAT (`glpat-[A-Za-z0-9_-]{20}`)
  - Slack bot/user/app tokens (`xox[baprs]-...`)
  - Stripe live + test (`sk_live_`, `sk_test_`, `pk_live_`)
  - Twilio (`SK[a-f0-9]{32}`)
  - SendGrid (`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)
  - Generic JWT (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
  - Private keys (PEM markers: `-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----`)
  - Google API key (`AIza[0-9A-Za-z_-]{35}`)
  - AWS Access Key (`AKIA[0-9A-Z]{16}`) ve `ASIA*` (session) ve `AGPA*` (group)
  - Azure storage account key (`[a-zA-Z0-9+/]{86}==`)
  - Database connection strings (`mongodb://.*:.*@`, `mysql://.*:.*@`, `postgres://.*:.*@`)
- [CC] Entropy filter: bir string'in Shannon entropy'si > 4.0 ise secret olarak değerlendir (yanlış negatifleri azaltır)
- [CC] Allowlist: `EXAMPLEKEY`, `XXXXXXXX`, `0000`, `1234`, `placeholder`, `example`, `dummy`, `test`, `fake` substring'lerini içeren string'ler **suppressible** olarak işaretle (severity=Info, not High)
- [CC] Dosya bazlı allowlist: `*test*.java`, `*Test*.java`, `*Mock*.java` dosyalarındaki secret'lar varsayılan olarak Info severity (override edilebilir)

### 2.3 Insecure Random

**Görevler:**
- [CC] `SC-JAVA-RAND-INSECURE` — `new Random()`, `Math.random()`, `ThreadLocalRandom.current().nextInt()` çağrıları, eğer aynı method'da `password|token|session|nonce|salt|secret|key|otp|csrf` substring'i varsa → High severity (CWE-330)
- [CC] Heuristic gerekli: sadece `new Random()` görünce Critical demek false positive üretir (oyun, simülasyon)

### 2.4 Information Disclosure

**Görevler:**
- [CC] `SC-JAVA-INFO-STACKTRACE` — `Exception.printStackTrace(response.getWriter())` veya `e.printStackTrace(out)` (CWE-209)
- [CC] `SC-JAVA-INFO-EXCEPTION-MSG` — `response.getWriter().println(e.getMessage())` veya `+ e.toString()` content yazma (CWE-209)

**Sprint 2 Çıkış Kriteri:** vulnerable-java-app coverage'ı %14 → %35'e çıkmış (~30 yeni finding).

---

## SPRINT 3 — Taint Engine Sink Genişletme (Hafta 5-6)

> **Amaç:** Mevcut interprocedural taint engine'in zaten çalıştığı bilgisinden yararlanarak, sink kataloguna yeni sink'ler ekle. Source ve propagator zaten var.

### 3.1 Source Kataloğu Audit

**Görevler:**
- [CC+H] `internal/sast/taint/sources.yaml` (veya muadili) dosyasını incele, mevcut Java source'ları listele
- [CC] Eksik olanları ekle:
  - `HttpServletRequest.getParameter(*)` ve tüm varyantları (`getParameterValues`, `getParameterMap`)
  - `HttpServletRequest.getHeader(*)`, `getHeaders`, `getHeaderNames`
  - `HttpServletRequest.getReader()`, `getInputStream()`
  - `HttpServletRequest.getCookies()` → `Cookie.getValue()`
  - `HttpServletRequest.getQueryString()`, `getRequestURI()`, `getRequestURL()`
  - Spring: `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@RequestBody`, `@CookieValue`, `@ModelAttribute` annotated parameters
  - JAX-RS: `@QueryParam`, `@PathParam`, `@HeaderParam`, `@CookieParam`, `@FormParam`
  - System: `System.getenv(*)`, `System.getProperty(*)`, `args[*]` (main method)
  - File: `Files.readAllBytes`, `Files.readAllLines`, `BufferedReader.readLine` (file content sometimes user-controlled)
  - Network: `Socket.getInputStream`, `URL.openStream`

### 3.2 SQL Injection Sink'leri

**Görevler:**
- [CC] `SC-JAVA-SQLI-001` — Sink'ler:
  - `Statement.execute(taint)`, `executeQuery(taint)`, `executeUpdate(taint)`, `addBatch(taint)`
  - `Connection.prepareStatement(taint)` — taint'in **string concat**'ten geldiğini tespit et (PreparedStatement adı doğru ama içeriği concat)
  - `Connection.prepareCall(taint)`
  - JDBC named: `NamedParameterJdbcTemplate.queryForList(taint, ...)`, `JdbcTemplate.execute(taint)`
  - Hibernate: `Session.createQuery(taint)`, `createSQLQuery(taint)`, `createNativeQuery(taint)`
  - JPA: `EntityManager.createQuery(taint)`, `createNativeQuery(taint)`
  - MyBatis: `@Select(taint)` annotation value (statik analiz zor — skip ilk versiyon)

**Detection logic:**
- Sink çağrısının argümanı **string concat / String.format / StringBuilder** içeriyor VE bir source'dan tainted ise → finding
- Argüman literal string ise → finding değil
- Argüman parametre ama `?` placeholder ile binding yapılmış (`setString` çağrısı var) → finding değil

### 3.3 Command Injection Sink'leri

**Görevler:**
- [CC] `SC-JAVA-CMDI-001` — Sink'ler:
  - `Runtime.getRuntime().exec(taint)` — String, String[], String[] env varyantları
  - `new ProcessBuilder(taint)` ve `.command(taint)`
  - `Desktop.getDesktop().open(taint)` (CWE-78 cousin)
  - Apache Commons Exec: `CommandLine.parse(taint)`, `DefaultExecutor.execute(taint)`

### 3.4 Path Traversal Sink'leri

**Görevler:**
- [CC] `SC-JAVA-PATH-001` — Sink'ler:
  - `new File(taint)`, `new File(parent, taint)`, `new FileInputStream(taint)`, `FileOutputStream`, `RandomAccessFile`, `FileReader`, `FileWriter`
  - `Paths.get(taint)`, `Path.of(taint)`
  - `Files.newInputStream(Paths.get(taint))`, `Files.newBufferedReader(...)`
  - Servlet: `request.getRequestDispatcher(taint).forward()` — server-side include
  - `getClass().getResourceAsStream(taint)` (resource'a erişim)

### 3.5 Zip Slip

**Görevler:**
- [CC] `SC-JAVA-ZIPSLIP-001` — Pattern:
  - `ZipEntry.getName()` çağrısı VE
  - Bunun sonucu `new File(...)` veya `new FileOutputStream(...)` çağrısına geçiyor VE
  - Aynı method'da `entry.getName().contains("..")` veya `Path.normalize()` kontrolü YOK
  - (Heuristic — false positive olabilir, severity=High but mark as `confidence: medium`)

### 3.6 SSRF Sink'leri

**Görevler:**
- [CC] `SC-JAVA-SSRF-001` — Sink'ler:
  - `new URL(taint).openConnection()` ve `.openStream()`
  - `HttpURLConnection.connect()` (URL taint ise)
  - Apache HttpClient: `HttpGet(taint)`, `HttpPost(taint)`, `client.execute(httpRequest)` (request URL'i taint)
  - OkHttp: `new Request.Builder().url(taint)`
  - Spring: `RestTemplate.getForObject(taint, ...)`, `WebClient.get().uri(taint)`
  - Java 11+: `HttpClient.send(HttpRequest.newBuilder().uri(URI.create(taint)))`

### 3.7 XSS Sink'leri (Reflected + Stored)

**Görevler:**
- [CC] `SC-JAVA-XSS-001` — Sink'ler:
  - `response.getWriter().print(taint)`, `println`, `write`, `printf`
  - `response.getOutputStream().write(taint)`
  - `PrintWriter.println(taint)` (eğer PrintWriter response writer ise — interprocedural callgraph zaten var, bunu yakalayabilmeli)
- [CC] **Encoding-aware**: eğer taint `OWASP ESAPI.encoder().encodeForHTML(...)` veya `HtmlUtils.htmlEscape(...)` veya `org.apache.commons.text.StringEscapeUtils.escapeHtml4(...)` veya `org.springframework.web.util.HtmlUtils.htmlEscape` veya `org.owasp.encoder.Encode.forHtml(...)` üzerinden geçtiyse → sanitize edilmiş, finding değil
- [CC] Sanitizer kataloguna ekle: `internal/sast/taint/sanitizers.yaml`

### 3.8 Open Redirect

**Görevler:**
- [CC] `SC-JAVA-OPEN-REDIRECT-001` — Sink'ler:
  - `response.sendRedirect(taint)`
  - `response.setHeader("Location", taint)`
  - Spring controller `return "redirect:" + taint` (string concat detection)
- [CC] Sanitizer: eğer URL whitelisted host'a karşı kontrol edilmişse skip (heuristic, opsiyonel)

### 3.9 LDAP Injection

**Görevler:**
- [CC] `SC-JAVA-LDAP-001` — Sink'ler:
  - `DirContext.search(name, taint, controls)` — filter argümanı (2. param) taint
  - `LdapTemplate.search(name, taint, ...)`
  - String concat ile filter inşası tespit edilmeli

**Sprint 3 Çıkış Kriteri:** vulnerable-java-app coverage'ı %35 → %65'e çıkmış. Taint trace'ler raporda görünüyor.

---

## SPRINT 4 — Framework + Deserialization + JSP (Hafta 7-8)

> **Amaç:** Spring/Hibernate/Jackson gibi framework'lere özgü sink'leri ekle. JSP scriptlet parse'ı için Java parser'ı extend et.

### 4.1 Spring Framework Rules

**Görevler:**
- [CC] `SC-JAVA-SPRING-SPEL-001` — `SpelExpressionParser.parseExpression(taint)` (CVE-2022-22963 pattern)
- [CC] `SC-JAVA-SPRING-EVAL-001` — `ScriptEngine.eval(taint)`, `Compilable.compile(taint)`
- [CC] `SC-JAVA-SPRING-REFLECTION-001` — `Class.forName(taint)`, `Method.invoke` ile taint method name
- [CC] `SC-JAVA-SPRING-VIEWNAME-001` — `@GetMapping` return value `return taint` (Spring view resolver injection — Spring4Shell-adjacent)
- [CC] `SC-JAVA-SPRING-MASS-ASSIGN-001` — `@ModelAttribute` ile bind edilen class'ın setter'ları arasında `setRole`, `setAdmin`, `setPermissions`, `setIsActive` gibi sensitive setter'lar varsa → mass assignment riski (heuristic, severity=Medium)
- [CC] `SC-JAVA-SPRING-CSRF-DISABLED` — `http.csrf().disable()` çağrısı, `@EnableWebSecurity` config'inde

### 4.2 Hibernate / JPA Rules

**Görevler:**
- [CC] `SC-JAVA-HIBERNATE-HQL-INJ` — `Session.createQuery(taint)`, HQL injection (zaten 3.2'de eklendi, ama burada Hibernate-specific severity ve CWE-564 mapping)
- [CC] `SC-JAVA-JPA-NATIVE-QUERY` — `EntityManager.createNativeQuery(taint)` — native SQL, daha riskli, severity=Critical

### 4.3 Deserialization Sink'leri

**Görevler:**
- [CC] `SC-JAVA-DESER-NATIVE` — `ObjectInputStream.readObject()` ve `readUnshared()` — input source'u tainted ise (zaten var, ama source tracking ekle: cookie, request body, file)
- [CC] `SC-JAVA-DESER-JACKSON-DEFAULT-TYPING` — `ObjectMapper.enableDefaultTyping()` veya `activateDefaultTyping(...)` çağrısı (CVE-2017-7525 pattern)
- [CC] `SC-JAVA-DESER-JACKSON-POLYMORPHIC` — `@JsonTypeInfo(use = Id.CLASS)` annotation
- [CC] `SC-JAVA-DESER-XSTREAM` — `XStream.fromXML(taint)` (önce XStream.allowTypes whitelist'i kontrol et — varsa sanitized say)
- [CC] `SC-JAVA-DESER-SNAKEYAML` — `new Yaml().load(taint)` — eğer constructor `SafeConstructor` değilse (varsayılan unsafe) (CVE-2022-1471)
- [CC] `SC-JAVA-DESER-XMLDECODER` — `new XMLDecoder(taint).readObject()` — her zaman tehlikeli

### 4.4 XXE — Secure Configuration Kontrolü

**Görevler:**
- [CC] `SC-JAVA-XXE-001` — Pattern:
  - `DocumentBuilderFactory.newInstance()` çağrılıyor VE
  - Aynı method'da şu setFeature'ların **HİÇBİRİ** yok:
    - `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` veya
    - `setFeature("http://xml.org/sax/features/external-general-entities", false)` veya
    - `setExpandEntityReferences(false)` + diğer disable'lar
  - VE sonra `parse(taint)` çağrılıyor → finding
- [CC] Aynısı `SAXParserFactory`, `XMLReader`, `XMLInputFactory` (StAX), `SchemaFactory`, `TransformerFactory`, `Validator` için de
- [CC] Heuristic: eğer aynı class veya parent class'ta XML parser secure config helper var ve çağrılıyorsa → skip (interprocedural callgraph kullan)

### 4.5 JSP Scriptlet Tarama

**Görevler:**
- [CC+H] `internal/sast/frontend/jsp/` yeni paket
- [CC] JSP lexer: `<%`, `<%=`, `<%!`, `<%@`, `<jsp:...>` directive'lerini tanı
- [CC] Scriptlet içeriğini Java fragment olarak çıkar (her `<% ... %>` bir Java statement bloğu)
- [CC] Mevcut Java parser'ı bu fragment'lere çağır (zaten var, reuse)
- [CC] Source: `request.getParameter(...)` JSP'de de geçerli, mevcut taint engine direkt çalışmalı
- [CC] Yeni rule: `SC-JSP-SCRIPTLET-WARN` — JSP'de scriptlet kullanımı (best-practice violation, severity=Info)
- [CC] EL expressions tarama: `${taint}` — eğer EL ifadesi tainted ise XSS (Spring EL parser'ından farklı — JSP EL)

**Test:**
- [CC] `vulnerable-java-app/src/main/webapp/index.jsp` üzerinde scan çalıştır, en az 4 finding bekle (XSS, SQLi, command, redirect)

### 4.6 Web.xml + Properties + YAML Tarama

**Görevler:**
- [CC] `internal/sast/frontend/xml/` — XML parser (stdlib `encoding/xml` yeter)
- [CC] `internal/sast/frontend/properties/` — Java .properties parser (basit `key=value` lexer)
- [CC] `internal/sast/frontend/yaml/` — `gopkg.in/yaml.v3` (sadece bu dış dep'i kabul et, çünkü YAML manuel yazmak çok masraflı)
- [CC] Yeni rules:
  - `SC-CONFIG-WEBXML-INSECURE-COOKIE` — `<http-only>false</http-only>` veya `<secure>false</secure>`
  - `SC-CONFIG-WEBXML-LONG-SESSION` — `<session-timeout>` > 60
  - `SC-CONFIG-WEBXML-URL-TRACKING` — `<tracking-mode>URL</tracking-mode>`
  - `SC-CONFIG-WEBXML-NO-AUTH-CONSTRAINT` — `<servlet-mapping>` var ama `<security-constraint>` yok (heuristic)
  - `SC-CONFIG-PROPS-SECRET` — properties dosyasında secret pattern (mevcut secret regex'i .properties'e de uygula)
  - `SC-CONFIG-PROPS-DEBUG-PROD` — `debug=true`, `show.stacktrace=true`, `trust.all.certs=true`
  - `SC-CONFIG-YAML-SECRET` — application.yml'da secret

**Sprint 4 Çıkış Kriteri:** vulnerable-java-app coverage'ı %65 → %85'e çıkmış. JSP, XML, properties dosyaları taranıyor.

---

## SPRINT 5 — SCA + Vulnerable Dependencies (Hafta 9-10)

> **Amaç:** pom.xml ve build.gradle'daki dependency'leri parse et, OSV.dev API'sine sor, CVE eşle.

### 5.1 Dependency Parser

**Görevler:**
- [CC] `internal/sca/parser/maven/` — pom.xml parser (mevcut XML parser'ı kullan)
  - `<dependency>` blokları
  - `<properties>` ile version interpolation (`${spring.version}` gibi)
  - `<dependencyManagement>` parent POM (basit ilk versiyon — parent POM çözümleme yok, sadece direct deps)
- [CC] `internal/sca/parser/gradle/` — build.gradle.kts ve build.gradle
  - Regex-based ilk versiyon (Groovy/Kotlin DSL parse zor, MVP'de string match yeter)
  - `implementation 'group:artifact:version'` ve `implementation("group:artifact:version")` formatları
- [CC] `internal/sca/parser/npm/` — package.json (gelecek için, JS desteği için)
- [CC] `internal/sca/parser/python/` — requirements.txt + pyproject.toml

**Output:** `[]Dependency{Group, Artifact, Version, Scope, FilePath, LineNumber}`

### 5.2 CVE Database Integration

**Görevler:**
- [CC+H] OSV.dev API entegrasyonu (`https://api.osv.dev/v1/query`)
- [CC] Cache layer: `internal/sca/cache/` — TTL'li disk cache, her dependency için 24 saat (rate limit'i koru)
- [CC] Batch query: tek HTTP call'da N dependency sorgula (`POST /v1/querybatch`)
- [CC] Response parsing: vulnerability id (CVE-* veya GHSA-*), severity (CVSS), affected versions, fixed versions, references

**Alternatif/yedek:** GitHub Advisory Database (`https://github.com/advisories`) JSON dump (offline, daha hızlı ama güncellik riski)

### 5.3 SCA Findings

**Görevler:**
- [CC] Yeni finding tipi: `Type: SCA` (mevcut SAST/SECRET/DAST'ın yanına)
- [CC] Rule kataloglarına ekle: `SC-SCA-CVE-MATCH` — bir dependency'nin known CVE'si var
- [CC] Severity mapping: CVSS 9.0+ → Critical, 7.0-8.9 → High, 4.0-6.9 → Medium, < 4.0 → Low
- [CC] Finding metadata: CVE ID, fixed version (önerilen upgrade), dependency path
- [CC] Reachability hint (opsiyonel ama değerli): eğer SAST tarafı bu dependency'nin import edildiğini gördüyse `reachable: true` flag (ör. log4j-core import'u var → Log4Shell reachable)

### 5.4 Test

**Görevler:**
- [CC] vulnerable-java-app/pom.xml üzerinde scan
- [CC] Beklenen CVE'ler:
  - log4j-core 2.14.1 → CVE-2021-44228 (Log4Shell), CVE-2021-45046, CVE-2021-45105
  - struts2-core 2.3.32 → CVE-2017-5638
  - spring-webmvc 5.3.17 → CVE-2022-22965 (Spring4Shell)
  - jackson-databind 2.9.8 → çoklu CVE
  - commons-collections 3.2.1 → CVE-2015-6420
  - snakeyaml 1.29 → CVE-2022-1471
  - xstream 1.4.17 → CVE-2021-39139
  - dom4j 1.6.1 → CVE-2020-10683
  - bcprov-jdk15on 1.55 → çoklu CVE
  - mysql-connector-java 5.1.46 → CVE-2017-3589, CVE-2019-2692
- [CC] Toplam ≥15 SCA finding bekleniyor

**Sprint 5 Çıkış Kriteri:** vulnerable-java-app full scan: SAST coverage %85 + 15+ SCA finding = ~120+ finding (deduplicated, severity-correct).

---

## SPRINT 6 — Ekosistem: SARIF, IDE, CI (Hafta 11-12)

> **Amaç:** SentinelCore'u kurumsal ekosisteme bağla. Boyner kurumsal kullanım + Teknokent başvurusu için showcase.

### 6.1 SARIF 2.1.0 Export

**Görevler:**
- [CC] `internal/sast/report/sarif/` paketi
- [CC] [SARIF 2.1.0 spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) tam uyum
- [CC] Mapping:
  - `Run.tool.driver.name` = "SentinelCore"
  - `Run.tool.driver.version` = build version
  - `Run.tool.driver.rules[]` — tüm aktif kurallar metadata ile
  - `Run.results[]` — finding'ler
  - `Result.ruleId`, `Result.level` (error/warning/note), `Result.message.text`
  - `Result.locations[].physicalLocation.artifactLocation.uri` (file path)
  - `Result.locations[].physicalLocation.region.startLine/startColumn`
  - `Result.codeFlows[]` — taint trace (source → propagator → sink) zincirini SARIF code flow olarak göster
  - `Result.partialFingerprints` — dedup için stable fingerprint
  - `Result.properties` — `cwe`, `owasp`, `cvss`, `vuln_class` custom properties
- [CC] CLI flag: `--format sarif` veya `--format json,sarif,markdown` (multi-format)
- [CC] Validation: SARIF Validator (`https://sarifweb.azurewebsites.net/Validation`) ile valid olduğunu confirm et

**Test:**
- [CC] vulnerable-java-app scan'i SARIF'e çevir
- [CC] GitHub Code Scanning'e upload simülasyonu (gh CLI ile)
- [CC] Microsoft SARIF Viewer (VS Code extension) ile aç, finding'lerin doğru göründüğünü check et

### 6.2 SonarQube Generic Issue Format Export

**Görevler:**
- [CC] `internal/sast/report/sonarqube/` — Generic Issue Data format ([docs](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-data/))
- [CC] CLI flag: `--format sonar-generic`

### 6.3 GitLab Security Report Format

**Görevler:**
- [CC] `internal/sast/report/gitlab/` — GitLab SAST report schema ([docs](https://docs.gitlab.com/ee/user/application_security/sast/#output))
- [CC] CLI flag: `--format gitlab-sast`
- [CC] CI sample: `.gitlab-ci.yml` örneği — Boyner'ın muhtemelen GitLab kullanıyor olduğunu varsayarak

### 6.4 VS Code Extension MVP

**Görevler:**
- [CC+H] Yeni repo: `sentinelcore-vscode/`
- [CC] TypeScript + VS Code Extension API
- [CC] Komut: "SentinelCore: Scan Workspace" → CLI'yi spawn et, SARIF al
- [CC] Inline diagnostics: VS Code Problems panel'de finding'ler
- [CC] Hover: finding üzerine hover edince description + how-to-fix göster
- [CC] Code action (lightbulb): bazı kurallar için suggested fix (ör. `MessageDigest.getInstance("MD5")` → `"SHA-256"` quick-fix)
- [CC] Marketplace publish değil, .vsix dosyası release et (Boyner internal kullanım için yeter)

### 6.5 GitHub Action / GitLab Template

**Görevler:**
- [CC] `actions/sentinelcore-scan/action.yml` — composite action
- [CC] Inputs: `path`, `format`, `fail-on-severity`
- [CC] Outputs: SARIF artifact, finding count
- [CC] README + usage example
- [CC] GitLab CI template: `.gitlab-ci-templates/sentinelcore-sast.yml`

### 6.6 Performance Benchmark + Profile

**Görevler:**
- [CC] `tests/perf/` benchmark suite
  - vulnerable-java-app scan time baseline
  - Büyük açık kaynak proje (örn. Spring Boot, Apache Tomcat) scan time
  - Memory peak
- [CC] Profil: `go tool pprof` ile CPU + memory profili al, hot path'leri belgeleyip GitHub issue açan script

### 6.7 Dokümantasyon

**Görevler:**
- [CC] `docs/RULES.md` — tüm 150+ kuralın listesi (auto-generate edilir, rule metadata'sından)
- [CC] `docs/ARCHITECTURE.md` — engine bileşenleri, data flow diagramı
- [CC] `docs/RULE_AUTHORING.md` — yeni rule nasıl yazılır, bir örnek + template
- [CC] `docs/COVERAGE.md` — vulnerable-java-app sonuç tablosu, hangi CWE/OWASP kategoriler kapsanıyor
- [CC] README güncellenmiş — quick start, use cases, integration matrix

**Sprint 6 Çıkış Kriteri:**
- SARIF export valid
- VS Code extension çalışıyor (.vsix yüklenebilir)
- GitLab/GitHub CI template hazır
- vulnerable-java-app scan time benchmark'ı kayıtlı
- 150+ kural dökümante edilmiş

---

## EK — Teknokent Başvurusu İçin Patentlenebilir Novelty Argümanları

Bu plan tamamlandıktan sonra TÜRKPATENT başvurusu için defansif olarak öne çıkarılabilecek noktalar (yasal değerlendirme için patent vekiliyle konuşmak gerekir, bunlar ön analiz):

1. **Multi-language unified IR** — 4 dilden tek IR'a çıkarma (yaygın değil; Semgrep ayrı pattern, CodeQL ayrı QL — IR seviyesinde unified mi rakipler? incelenmeli)
2. **Reachability-aware SCA** — SCA bulgusunu SAST callgraph'ı ile birleştirip "bu CVE bu projede gerçekten erişilebilir mi" bilgisi (Snyk benzer şey yapıyor — diff bul)
3. **Confidence-tiered finding model** — heuristic vs deterministik kuralları "confidence: high/medium/low" ile etiketleme
4. **Sanitizer-aware taint** — sanitizer kataloğu ile path-sensitive taint propagation (bu da yaygın, novelty düşük)
5. **El yazımı pure-Go parser stack (no JNI/sidecar)** — performans + deployment basitliği bir pratik avantaj, novelty değil ama mühendislik artısı

**Tavsiye:** Patent başvurusunu Sprint 4-5 sonunda, somut bir engine + benchmark + test corpus elinde olduğunda yap. Erken patent → savunması zor olur.

---

## EK 2 — Test Corpus Stratejisi

vulnerable-java-app tek başına yetmez. Ek corpus önerileri:

- [H] **OWASP Benchmark v1.2** — endüstri standardı SAST benchmark, true positive rate hesaplanabilir (metrik objektif)
- [H] **Juliet Test Suite (Java)** — NIST test corpus, CWE bazlı kapsam ölçümü
- [H] **Secrets-test-repo** — TruffleHog, Gitleaks, detect-secrets'ın test corpus'larını mirror et
- [H] **Real-world OSS**: Apache Tomcat, Spring Petclinic, Juice Shop (deliberate vulnerable) — gerçek dünya testi

`tests/regression/` altında bunlar ayrı klasörlerde dursun, her biri için coverage % raporu üretilsin.

---

## EK 3 — Risk ve Bağımlılıklar

**Yüksek risk noktaları:**
- **JSP scriptlet parse'ı (Sprint 4.5)** — JSP grammar karmaşık, JSP 2.x EL ifadeleri ekstra parser ister. Kapsamı sadece scriptlet (`<% %>`) ile sınırla, EL'i Sprint 7'ye ertele
- **Maven parent POM çözümleme (Sprint 5.1)** — full Maven dependency resolution kompleks (dependency conflict, exclusions). MVP: sadece direct dependencies. Transitive'leri Sprint 7'de
- **OSV.dev rate limit** — 1000 req/dk, batch query kullan, cache şart
- **SARIF spec uyumu** — sandbox'a code flow'lar zor mapping. Microsoft Validator + JSON schema ile test et

**External dependencies (bilinçli kabul):**
- `gopkg.in/yaml.v3` (Sprint 4.6 — YAML parser yazmak gereksiz masraf)
- `github.com/...` HTTP client (OSV.dev için stdlib `net/http` yeter aslında)

**Diğer her şey stdlib + internal — bu mevcut "no external dep" prensibini koruyor.**

---

## Sprint Sonu Self-Check Soruları

Her sprint sonunda Claude Code'a sor:

1. Bu sprint'te beklenen tüm dosyalar oluşturuldu mu?
2. Regression test coverage % artışı plana uygun mu?
3. Yeni eklenen kuralların hepsinin pozitif + negatif testi var mı?
4. Mevcut testler hâlâ geçiyor mu (no regression)?
5. Yeni external dependency eklendi mi? Eklendiyse gerekçesi `docs/DEPENDENCIES.md`'de mi?
6. CHANGELOG.md güncellendi mi?
7. Performance benchmark sapma var mı (>%20 yavaşlama varsa profil çıkar)?

---

## Bitiş Tanımı (12 Hafta Sonu)

- [ ] vulnerable-java-app coverage **≥%85**
- [ ] Toplam aktif rule sayısı **≥150**
- [ ] SCA modülü çalışıyor, OSV.dev entegre
- [ ] SARIF + GitLab + Sonar export'ları valid
- [ ] VS Code extension `.vsix` yüklenip çalışıyor
- [ ] GitHub Action + GitLab CI template public
- [ ] Tüm yeni kurallar dokümante (`docs/RULES.md` auto-generated)
- [ ] OWASP Benchmark üzerinde çalışan ilk skor (sayı kaç çıkarsa baseline'dır)
- [ ] No regression: mevcut Boyner deployment'ı testleri geçiyor

---

*Hazırlayan tarih: Mayıs 2026*
*Son güncelleme: Sprint başına haftalık review*
