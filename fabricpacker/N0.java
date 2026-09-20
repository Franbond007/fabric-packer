package fabricpacker;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Fixed-name JNI anchor for the native crypto core.
 *
 * The class name, the native method names below and the exported symbols in
 * the native core library must stay in sync, so this class is deliberately
 * excluded from the per-build loader renaming. It contains no logic of its own:
 * the real AES key is derived from Java-visible material XOR a native HKDF mask
 * and lives exclusively inside the native library, so it never appears on the
 * Java heap. There is deliberately no Java fallback path - if the native core
 * cannot be loaded the packed loader refuses to run.
 *
 * The public helper methods use neutral names (nk/nd/nx) on purpose so the
 * compiled class carries no plaintext crypto vocabulary.
 */
final class N0 {
    /** Optional absolute path override, used by the build-time self-test. */
    private static final String OVERRIDE_PROPERTY = "fabricpacker.native.core";

    private static boolean loaded;
    private static Throwable loadFailure;

    private N0() {
    }

    private static synchronized void ensureLoaded() {
        if (loaded || loadFailure != null) return;
        try {
            Path library;
            String override = System.getProperty(OVERRIDE_PROPERTY);
            if (override != null && !override.isBlank()) {
                library = Path.of(override);
                if (!Files.isRegularFile(library)) {
                    throw new IllegalStateException("native core override missing");
                }
            } else {
                String base = A0.n();
                if (base == null || base.isBlank()) {
                    throw new IllegalStateException("native core disabled");
                }
                library = extractNativeCore(base + libExt());
            }
            System.load(library.toAbsolutePath().toString());
            if (n4() != 20260920) throw new IllegalStateException("native core version mismatch");
            loaded = true;
        } catch (Throwable failure) {
            loadFailure = failure;
        }
    }

    /** Extracts the native core from the JAR (or a dev filesystem path) into a private temp dir. */
    private static Path extractNativeCore(String resource) throws IOException {
        byte[] bytes = null;
        try (InputStream input = N0.class.getClassLoader().getResourceAsStream(resource)) {
            if (input != null) bytes = input.readAllBytes();
        }
        if (bytes == null) {
            Path file = Path.of(resource);
            if (Files.isRegularFile(file)) bytes = Files.readAllBytes(file);
        }
        if (bytes == null || bytes.length == 0) throw new IOException("native core missing: " + resource);
        Path dir = Path.of(System.getProperty("java.io.tmpdir"),
                "fabricpacker-core-" + Long.toHexString(ProcessHandle.current().pid()));
        Files.createDirectories(dir);
        // Random target name so the path is not predictable/pre-placeable.
        Path target = dir.resolve("c" + Long.toHexString(
                new java.security.SecureRandom().nextLong()) + libExt());
        Files.write(target, bytes);
        // Guard against a swap between write and load: the file we are about to
        // load must byte-match what we extracted. Direct compare avoids pulling
        // a hash-algorithm string literal into this shipped class.
        byte[] back = Files.readAllBytes(target);
        if (!java.util.Arrays.equals(bytes, back)) {
            try {
                Files.deleteIfExists(target);
            } catch (IOException ignored) {
            }
            throw new IOException("native core integrity check failed");
        }
        return target;
    }

    /** Derives the AES key natively from the Java-visible material; returns an opaque handle. */
    static long nk(byte[] material, byte[] salt, byte[] info) {
        ensureLoaded();
        if (!loaded) throw new IllegalStateException("native core unavailable", loadFailure);
        long handle = n2(material, salt, info);
        if (handle == 0) throw new IllegalStateException("native key init failed");
        return handle;
    }

    /** Decrypts one AES-GCM blob (ciphertext with trailing 128-bit tag) inside the container. */
    static byte[] nd(long handle, byte[] nonce, byte[] aad, byte[] container, int offset, int length) {
        ensureLoaded();
        if (!loaded) throw new IllegalStateException("native core unavailable", loadFailure);
        byte[] plain = n1(handle, nonce, aad, container, offset, length);
        if (plain == null) throw new IllegalStateException("native core rejected the input");
        return plain;
    }

    /** Destroys the native key material (called when the loader closes). */
    static void nx(long handle) {
        if (loaded && handle != 0) n3(handle);
    }

    /** Shared-library extension for the current OS. */
    private static String libExt() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) return ".dylib";
        if (os.contains("win")) return ".dll";
        return ".so";
    }

    /** Native debugger probe: nonzero bitmask = debugger/agent present, 0 = clean. */
    static int nD() {
        try {
            ensureLoaded();
            if (!loaded) return 0;
            return n5();
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /** Native window-title scan for RE/dump-tool GUIs: 1 = found, 0 = clean. */
    static int nW() {
        try {
            ensureLoaded();
            if (!loaded) return 0;
            return n6();
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /** Deep native scan (processes, injected modules, hardware breakpoints). */
    static int nP() {
        try {
            ensureLoaded();
            if (!loaded) return 0;
            return n7();
        } catch (Throwable ignored) {
            return 0;
        }
    }

    private static native byte[] n0(byte[] data);
    private static native long n2(byte[] material, byte[] salt, byte[] info);
    private static native byte[] n1(long handle, byte[] nonce, byte[] aad, byte[] container, int offset, int length);
    private static native void n3(long handle);
    private static native int n4();
    private static native int n5();
    private static native int n6();
    private static native int n7();
}
