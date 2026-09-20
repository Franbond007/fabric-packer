# Fabric Packer

Der Packer verarbeitet das von Loom erzeugte remappte JAR und verpackt alle
geschützten Klassen und Ressourcen in einen verschlüsselten, signierten
In-Memory-Payload, den ein generierter Fabric-Loader zur Laufzeit entschlüsselt.
Die eigentliche AES-Entschlüsselung läuft ausschließlich in einem nativen
Krypto-Core (`packcore.dll`); der echte Schlüssel existiert nie auf dem
Java-Heap (siehe [Nativer Krypto-Core](#nativer-krypto-core)).

## Voraussetzungen

- **JDK 21** zum Bauen und zum Ausführen des Packers (der Packer kompiliert
  während des Packvorgangs die Loader-Teile und braucht daher ein JDK, keine JRE)
- Windows PowerShell für `build.ps1`
- **clang / LLVM-MinGW** zum Bauen des nativen Krypto-Cores (`packcore.dll`).
  `build.ps1` baut ihn automatisch mit, falls `clang` im PATH ist; andernfalls
  wird eine vorhandene `native/packcore.dll` wiederverwendet.
- Für Linux/macOS zusätzlich `native/packcore.so` bzw. `packcore.dylib` (per
  `native/build-native.sh` oder GitHub-CI, siehe [Plattformen](#plattformen)).
- Der Packer bettet beim Packen alle in `native/` vorhandenen Bibliotheken ein;
  der gepackte Mod läuft auf den Plattformen, deren Bibliothek eingebettet ist.

## Schnellstart

```powershell
.\build.ps1          # kompiliert fabricpacker/ und erzeugt fabric-packer.jar
.\build.ps1 -Test    # zusätzlich Unit-Tests (fabricpacker.TestRunner)
.\build.ps1 -Smoke   # zusätzlich Smoke-Test: Beispiel-Mod wird gepackt
.\build.ps1 -All     # Build + Tests + Smoke-Test
```

## Nutzung

```powershell
java -jar fabric-packer.jar C:\Pfad\mod-remapped.jar C:\Pfad\config.json
```

Die Konfigurationsdatei ist optional; fehlt sie, wird `pack-config.json` im
aktuellen Verzeichnis verwendet, falls vorhanden. Optionen:

| Option | Bedeutung |
| --- | --- |
| `--output <pfad>` | Ausgabe-JAR (Standard: `packed-fabric.jar` neben der Eingabe) |
| `--exclude <pfad>` | Klasse/Ressource zusätzlich sichtbar halten (mehrfach möglich) |
| `--watermark <id>` | Kunden-Wasserzeichen statt Zufall (Leak-Rückverfolgung) |
| `--compression <1-9>` | zlib-Kompressionsstufe (Standard: 9) |
| `--parallel <1-32>` | Parallele Verschlüsselung der Einträge (Standard: CPU-Kerne) |
| `--quiet` | Nur Fehler ausgeben |
| `--verbose` | Stacktraces bei Fehlern anzeigen |
| `--help` | Hilfe anzeigen |

Exit-Codes: `0` erfolgreich, `1` Fehler, `2` falsche Argumente.

## Konfiguration (`config.json`)

```json
{
  "class": ["com.example.KnownVisibleClass"],
  "resources": ["assets/meine_datei.txt"],
  "leakTerms": ["MeinGeheimerFeatureName"],
  "compression": 9,
  "parallelism": 8
}
```

- `class`, `classes`, `exempt`: Klassen oder Pakete (Punktnotation), die
  sichtbar bleiben (Entrypoints, Mixins und Fabric-Metadaten bleiben immer
  automatisch sichtbar).
- `resources`: Ressourcenpfade, die sichtbar bleiben.
- `leakTerms`: zusätzliche Begriffe für den Leak-Check sichtbarer Dateien.
- `compression`: 1–9 (Standard 9).
- `parallelism`: 1–32 Threads für Kompression/Verschlüsselung (Standard: CPU-Kerne).
- Unbekannte Schlüssel ergeben eine Warnung, falsche Werte brechen den Build ab.

## Nativer Krypto-Core

Die AES-256-GCM-Entschlüsselung des Payloads läuft ausschließlich in
`native/packcore.dll` (JNI-Anker: die fest benannte Klasse `fabricpacker.N0`).

- Der echte Schlüssel wird nativ als
  `material XOR HKDF-SHA256(ikm = BAKED_IKM, salt, info)` abgeleitet und lebt nur
  in einem Slot innerhalb der DLL. Auf dem Java-Heap liegt nur das `material`
  (verteilt über A0/A1/A2) sowie `salt`/`info` (`A0.h()`/`A0.i()`) — ohne die
  DLL ergibt reines Java-Bytecode nur einen wertlosen Decoy.
- Das IKM ist im Binary eingebacken (`native/pk_sha1.h`), aber **nicht als
  klare 32-Byte-Konstante**: es liegt gesplittet als `PK_K0 XOR PK_K1` vor und
  wird nur kurz zur Laufzeit in `hkdf_mask` rekonstruiert. Es wird an Mod-Nutzer
  nie ausgeliefert. Eine build-seitige Kopie steht in `FabricPacker.BAKED_IKM`
  (= `PK_K0 XOR PK_K1`), damit der Packer `material` berechnen kann. **Alle drei
  müssen übereinstimmen und werden pro Release rotiert.** Ein Build-Self-Test
  (`runNativeSelfTest`) entschlüsselt bei jedem Pack einen echten Blob durch die
  reale DLL und bricht ab, falls Java- und C-HKDF auseinanderlaufen.
- Die DLL wird mit gestripptem Symboltable gebaut (`-s`,
  `--exclude-all-symbols`), sodass nur die JNI-Einstiegspunkte exportiert sind.
- Vor `System.load` prüft der Loader, dass die nach `%TEMP%` extrahierte DLL
  byte-genau der eingebetteten Resource entspricht (Schutz gegen Datei-Swap).
- Es gibt bewusst keinen Java-Fallback: fehlt die DLL oder passt die
  Core-Version (`n4()`) nicht, verweigert der Loader den Start.
- Grenzen: Der Schutz erschwert statische Extraktion. Ein Angreifer, der den
  Client ausführt, kann weiterhin den entschlüsselten Speicher oder die native
  Schnittstelle beobachten.

### Plattformen

Der Loader lädt pro OS die passende Bibliothek (`packcore.dll` / `packcore.so` /
`packcore.dylib`) und der Packer bettet **alle** ein, die beim Packen in `native/`
liegen. Ein gepackter Mod läuft auf den Plattformen, deren Bibliothek eingebettet
ist. Bauen:

```powershell
.\native\build-native.ps1        # Windows  -> native/packcore.dll (clang/LLVM-MinGW)
```
```bash
JAVA_HOME=/pfad/zum/jdk ./native/build-native.sh   # Linux -> .so, macOS -> .dylib
```

Linux/macOS bequem per CI: `.github/workflows/native.yml` baut `packcore.so`
(Ubuntu) und `packcore.dylib` (macOS) und lädt sie als Artefakte hoch. Lade sie
herunter, lege sie in `native/`, dann packen — der Packer bettet alle drei ein.
Ohne die jeweilige Bibliothek verweigert der Loader auf dem Ziel-OS den Start
(kein Fallback).

## Anti-Tamper (lokal, ohne Server)

Jeder gepackte Mod enthält eine Schutz-Klasse (`fabricpacker.Guard`, pro Build
umbenannt), die **rein lokal** auf Manipulation prüft und bei einem Treffer den
JVM-Prozess **hart beendet** (`Runtime.halt`) — das Spiel schließt sich bzw.
öffnet gar nicht erst. Keine Netzwerknutzung, kein Report, kein Ban-Server.

Der Check läuft beim Start (`preLaunch` **und** im Loader-Konstruktor, bevor
irgendetwas entschlüsselt wird) und danach als niedrigpriorer Daemon alle 3 s.
Erkannt werden:

- **Debugger**: `-agentlib:jdwp` / `-Xdebug` / `-Xrunjdwp` in JVM-Args oder
  `JAVA_TOOL_OPTIONS`/`_JAVA_OPTIONS`, jdwp-/JDI-Threads, sowie **nativ**
  (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `NtGlobalFlag`) über
  den Krypto-Core — nativ ist am schwersten wegzupatchen.
- **RE-/Dump-Tool-Fenster (nativ)**: `Guard` scannt über den Core sichtbare
  Fenstertitel (`EnumWindows`) nach JByteMod, Recaf, Bytecode Viewer, Threadtear,
  Ghidra, x64dbg, dnSpy, Cheat Engine, JD-GUI. Das fängt GUI-Tools zuverlässig,
  auch wenn sie – wie JByteMod – **dynamisch** einen Agent anhängen (der taucht
  nicht in den Start-Argumenten auf) und als gewöhnlicher `javaw`-Prozess laufen.
- **Java-Agents / Dumper**: geblacklistete `-javaagent`-Namen und im Prozess
  geladene RE-Tool-Klassen/-Pakete.
- **RE-/Dump-Prozesse, injizierte Module & Hardware-Breakpoints (nativ)**: der
  Core scannt via `CreateToolhelp32Snapshot` laufende Prozesse (IDA, x64dbg,
  Ghidra, dnSpy, Cheat Engine, Process Hacker, Wireshark, JByteMod, Task-Manager,
  … Liste in `native/pk_jni.h`), geladene Module (Frida-Injection) und die
  Debug-Register aller Threads (gesetzte Hardware-Breakpoints). Nativ statt per
  sichtbarem `tasklist` — schwerer zu patchen und ohne Klartext-Liste in Java.

**Empfehlung (härtester Schutz gegen Dynamic-Attach):** Starte den Client mit
`-XX:+DisableAttachMechanism`. Dann verweigert die JVM selbst jedes nachträgliche
Anhängen eines Agents — JByteMod/Recaf können sich gar nicht erst attachen, kein
Patchen nötig. Der Fenster-/Prozess-Scan von `Guard` ist die Verteidigung für
den Fall, dass dieser Flag nicht gesetzt werden kann.

Wichtig und ehrlich: Das erhöht die Hürde gegen den **einzigen** Angriff, den die
Verschlüsselung allein nicht stoppen kann (ein Runtime-Dump des entschlüsselten
Bytecodes). Ein Angreifer, der den Client kontrolliert, kann diese Klasse
patchen — es ist ein starker Bremsklotz, kein absoluter Schutz. Der Windows
Task-Manager ist auf Wunsch **enthalten** (`taskmgr` per Prozessname + Fenstertitel);
das schließt das Spiel auch, sobald ein Spieler nur den Task-Manager öffnet —
entferne `taskmgr` aus `Guard.BAD_PROCESSES` und den Fenstertiteln, falls das zu
viele Fehlschließungen verursacht.

## Signierung

Die Ausgabe wird mit Ed25519 signiert. Für einen normalen Build werden ein
externer PKCS#8-Privatschlüssel und ein X.509-Public-Key benötigt, angegeben
entweder per System-Property oder Umgebungsvariable:

```powershell
java `
  -Dfabricpacker.signing.privateKey=C:\sicherer\build\signing.pk8 `
  -Dfabricpacker.signing.publicKey=C:\sicherer\build\signing.pub `
  -jar fabric-packer.jar C:\Pfad\mod-remapped.jar C:\Pfad\config.json
```

Alternativ: `$env:FABRICPACKER_SIGNING_PRIVATE_KEY` und
`$env:FABRICPACKER_SIGNING_PUBLIC_KEY`.

Für lokale Tests erzeugt `-Dfabricpacker.signing.generate=true` ein flüchtiges
Ed25519-Schlüsselpaar. Der private Schlüssel muss außerhalb des Projekt-,
JAR- und Ausgabeordners liegen.

## Wasserzeichen (Leak-Rückverfolgung)

Ohne Option ist das Wasserzeichen pro Build zufällig. Mit
`--watermark kunde-4711` werden stattdessen die ersten 24 Bytes von
`SHA-256("fabricpacker-watermark:kunde-4711")` eingebettet. Bei einem Leak
lassen sich verdächtige Kunden-IDs mit demselben Hash gegen die
`fabricpacker/w*.wm`-Ressource der geleakten JAR prüfen.

## Aufbau und Schutz der Ausgabe

- Die Ausgabe heißt `packed-fabric.jar` und liegt neben dem Eingabe-JAR.
- Der geschützte Inhalt liegt in einer pro Build zufällig benannten Datei
  unter `fabricpacker/p<zufällige-id>.dat`: verschlüsselter Index plus
  verschlüsselte Klassen und Ressourcen. Jeder Eintrag verwendet AES-256-GCM
  mit neuer zufälliger 12-Byte-Nonce und authentifizierten AAD-Daten. Header,
  Index-Tag, Eintragsreihenfolge, Indexaufbau und Loader-Namen ändern sich pro
  Build. Vor der Verschlüsselung wird jeder Eintrag mit zlib komprimiert,
  danach folgt zufälliges Padding; der Index speichert Original-, Kompressions-
  und Padding-Längen nur verschlüsselt.
- Es wird keine fertige 32-Byte-Schlüsselkonstante gespeichert. Im gepackten
  Mod liegt nur das über mehrere umbenannte Loader-Klassen (A0/A1/A2) verteilte
  *Material*; der echte AES-Schlüssel ergibt sich erst zur Laufzeit im nativen
  Core als `material XOR HKDF-SHA256(BAKED_IKM, salt, info)` und verlässt den
  nativen Speicher nie (siehe [Nativer Krypto-Core](#nativer-krypto-core)).
- Der Loader wird im Speicher installiert (preLaunch), entschlüsselt nur die
  angeforderte Klasse/Ressource und überschreibt temporäre Bytearrays.
  Entschlüsselte `.class`-Dateien landen nie auf der Festplatte.
- Der Loader implementiert neben `findClass`, `getResource` und
  `getResourceAsStream` auch `findResources`, damit Annotation-Scanner und
  Frameworks, die über `getResources(...)` enumerieren, gepackte Einträge
  finden (die Aufzählung liefert `fabricpacked://`-URLs, kein Verzeichnis-
  Listing).
- Signaturen: `fabricpacker/s<zufällige-id>.sig` enthält Hashes und Längen
  aller sichtbaren Loader-/Fabric-Einträge, des Payloads und des Indexbereichs
  und wird vor dem ersten Payload-Zugriff geprüft.
- Selbsttests nach jedem Build: Payload-Manipulationen (Nonce, GCM-Tag, AAD,
  Index, Padding, Kompression), Ed25519-Tamper-Fälle, Loader-Rewrite-Tests und
  ein Leak-Check, der sichtbare Dateien auf geschützte Namen und Begriffe
  prüft. Dabei werden keine Klassen aus dem Ziel-JAR ausgeführt.

## Tests

- `.\build.ps1 -Test` kompiliert `test/*.java` nach `testbuild/` und führt
  `fabricpacker.TestRunner` aus (JSON-Parser, Signaturformat, CLI- und
  Config-Parsing, Loader-Pfadvalidierung).
- `.\build.ps1 -Smoke` packt einen minimalen Beispiel-Mod
  (`test/sample-src`, `test/sample`) nach `test/smoke/` und führt dabei alle
  Build-Selbsttests aus.

## Bekannte Grenzen

- Fabric-Entrypoints, PreLaunch-Bootstrap, Mixins, Mixin-Konfigurationen,
  Refmaps, Fabric-Metadaten, Services und verschachtelte JARs bleiben
  sichtbar, weil Fabric sie vor oder außerhalb des eigenen ClassLoaders
  benötigt. Verschachtelte JARs (`META-INF/jars/*.jar`) sind damit ungeschützt.
- Der Schutz erschwert statisches Entpacken und einfache automatische
  Extraktion; er ist kein Schutz gegen einen Angreifer, der den Client
  ausführt und den entschlüsselten Speicher untersucht. Die Signatur erkennt
  Änderungen an Loader, Payload, Index und signierten Metadaten, verhindert
  aber kein Offline-Patching eines laufenden Java-Prozesses.
- Eingabe-JAR und Payload liegen während des Builds im Speicher; für sehr
  große Mods (> 200 MB) entsprechend viel RAM einplanen.
- Der gepackte Mod läuft nur auf den Plattformen, deren native Bibliothek beim
  Packen in `native/` lag (Windows/Linux/macOS). Anti-Debug gibt es auf allen
  drei; Fenster-Scan + Hardware-Breakpoint-Scan sind Windows-spezifisch, der
  Prozess-Scan läuft auf allen dreien. `PK_K0`/`PK_K1` (in `native/pk_sha1.h`)
  und `FabricPacker.BAKED_IKM` müssen synchron bleiben (`BAKED_IKM = PK_K0 XOR
  PK_K1`) und werden pro Release rotiert.
