# Fabric Packer Build (JDK 21)
# .\build.ps1          -> kompiliert und erzeugt fabric-packer.jar
# .\build.ps1 -Test    -> zusaetzlich Unit-Tests
# .\build.ps1 -Smoke   -> zusaetzlich Smoke-Test (Beispiel-Mod packen)
# .\build.ps1 -All     -> alles
param(
    [switch]$Test,
    [switch]$Smoke,
    [switch]$All
)
$ErrorActionPreference = 'Stop'
if ($All) { $Test = $true; $Smoke = $true }
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)

$buildOut = Join-Path (Get-Location) 'build'
if (Test-Path $buildOut) { Remove-Item -Recurse -Force $buildOut }
New-Item -ItemType Directory -Force -Path $buildOut | Out-Null

Write-Host '== Baue nativen Krypto-Core (packcore.dll) =='
# Der gepackte Loader entschluesselt ausschliesslich nativ. Der Core wird hier
# aus native/pk_*.h gebaut, damit DLL, Header und die BAKED_IKM-Kopie im Packer
# nie auseinanderlaufen; ohne clang wird eine vorhandene DLL wiederverwendet.
$nativeDll = Join-Path (Get-Location) 'native/packcore.dll'
if (Get-Command clang -ErrorAction SilentlyContinue) {
    & (Join-Path (Get-Location) 'native/build-native.ps1')
} elseif (-not (Test-Path $nativeDll)) {
    throw 'clang fehlt und native/packcore.dll ist nicht vorhanden - der Loader benoetigt den nativen Core'
} else {
    Write-Host 'clang nicht gefunden - verwende vorhandene native/packcore.dll'
}

Write-Host '== Kompiliere Packer (Java 21) =='
$sources = @(Get-ChildItem 'fabricpacker' -Filter '*.java' | ForEach-Object { $_.FullName })
$sources += @(Get-ChildItem 'net' -Recurse -Filter '*.java' | ForEach-Object { $_.FullName })
& javac --release 21 -encoding UTF-8 -d $buildOut @sources
if ($LASTEXITCODE -ne 0) { throw "javac fehlgeschlagen (Exit $LASTEXITCODE)" }

Write-Host '== Erzeuge fabric-packer.jar =='
& jar cfm fabric-packer.jar META-INF/MANIFEST.MF -C $buildOut .
if ($LASTEXITCODE -ne 0) { throw "jar fehlgeschlagen (Exit $LASTEXITCODE)" }

if ($Test) {
    Write-Host '== Kompiliere Tests =='
    $testOut = Join-Path (Get-Location) 'testbuild'
    if (Test-Path $testOut) { Remove-Item -Recurse -Force $testOut }
    New-Item -ItemType Directory -Force -Path $testOut | Out-Null
    $testSources = @($sources) + @(Get-ChildItem 'test' -Filter '*.java' | ForEach-Object { $_.FullName })
    & javac --release 21 -encoding UTF-8 -d $testOut @testSources
    if ($LASTEXITCODE -ne 0) { throw "javac (Tests) fehlgeschlagen (Exit $LASTEXITCODE)" }

    Write-Host '== Fuehre Tests aus =='
    & java -cp $testOut fabricpacker.TestRunner
    if ($LASTEXITCODE -ne 0) { throw "Tests fehlgeschlagen (Exit $LASTEXITCODE)" }
}

if ($Smoke) {
    Write-Host '== Smoke-Test: Packe Beispiel-Mod =='
    $smokeDir = Join-Path (Get-Location) 'test\smoke'
    if (Test-Path $smokeDir) { Remove-Item -Recurse -Force $smokeDir }
    New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null

    $sampleClasses = Join-Path $buildOut 'sample-classes'
    New-Item -ItemType Directory -Force -Path $sampleClasses | Out-Null
    & javac --release 21 -encoding UTF-8 -d $sampleClasses 'test\sample-src\com\example\Mod.java'
    if ($LASTEXITCODE -ne 0) { throw "javac (Beispiel-Mod) fehlgeschlagen (Exit $LASTEXITCODE)" }
    & jar cf "$smokeDir\sample-input.jar" -C 'test\sample' . -C $sampleClasses com
    if ($LASTEXITCODE -ne 0) { throw "jar (Beispiel-Mod) fehlgeschlagen (Exit $LASTEXITCODE)" }

    & java '-Dfabricpacker.signing.generate=true' -jar fabric-packer.jar "$smokeDir\sample-input.jar" 'test\smoke-config.json'
    if ($LASTEXITCODE -ne 0) { throw "Smoke-Pack fehlgeschlagen (Exit $LASTEXITCODE)" }
    if (-not (Test-Path "$smokeDir\packed-fabric.jar")) { throw 'packed-fabric.jar wurde nicht erzeugt' }
    Write-Host '== Smoke-Test bestanden =='
}

Write-Host '== Fertig =='
