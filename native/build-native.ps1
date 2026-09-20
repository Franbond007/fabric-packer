# Builds the native crypto core (packcore.dll) consumed by the packed loader.
# Requires: clang (LLVM-MinGW) and a JDK (jni.h). Output: native/packcore.dll
param([string]$Jdk = '')
$ErrorActionPreference = 'Stop'
$native = $PSScriptRoot
if (-not $Jdk) { $Jdk = $env:JAVA_HOME }
if (-not $Jdk -or -not (Test-Path (Join-Path $Jdk 'include/jni.h'))) {
    $line = (& java -XshowSettings:properties -version 2>&1 | Select-String 'java.home = ').ToString()
    $Jdk = (($line -split '=', 2)[1]).Trim()
}
if (-not (Test-Path (Join-Path $Jdk 'include/jni.h'))) { throw "JDK include not found (set JAVA_HOME): $Jdk" }
$clang = (Get-Command clang -ErrorAction SilentlyContinue).Source
if (-not $clang) { throw 'clang not found (LLVM-MinGW required)' }
$out = Join-Path $native 'packcore.dll'
$src = Join-Path $native 'packcore.c'
# -s strips the symbol table; --exclude-all-symbols keeps only the __declspec(dllexport)
# JNI entry points in the export table; -fvisibility=hidden hides internal functions.
& $clang -O2 -Wall -Wextra -std=c11 -D_WIN32_WINNT=0x0600 -fvisibility=hidden "-I$Jdk/include" "-I$Jdk/include/win32" -shared -static-libgcc -s "-Wl,--exclude-all-symbols" -o $out $src
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "native build failed (exit $LASTEXITCODE)" }
Write-Host ("Native core built: {0} ({1} bytes)" -f $out, (Get-Item $out).Length)
