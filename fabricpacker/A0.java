package fabricpacker;

import java.io.IOException;

/**
 * Build-time placeholder: PackedClassLoader is compiled against this API, while
 * the packed mod receives generated per-build parts that replace this class.
 * The values are benign so that unit tests can initialize loader classes safely;
 * this compiled placeholder is never copied into a packed output.
 */
final class A0 {
    private A0() {
    }

    static byte[] a() {
        return new byte[32];
    }

    static void b(ClassLoader loader) throws IOException {
        // Generated loader parts perform the real integrity check.
    }

    static byte[] c() {
        return new byte[16];
    }

    static byte[] d() {
        return new byte[16];
    }

    static int f() {
        return 1;
    }

    static byte[] g() {
        return new byte[44];
    }

    /** Native core base resource (per-build; per-OS extension appended by N0). */
    static String n() {
        return "native/packcore";
    }

    /** Per-build HKDF salt for the native key mask (zeros in the test placeholder). */
    static byte[] h() {
        return new byte[32];
    }

    /** Per-build HKDF info for the native key mask (zeros in the test placeholder). */
    static byte[] i() {
        return new byte[16];
    }

    static String e(int id) {
        return "packed-string-" + id;
    }
}
