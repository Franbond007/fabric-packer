package fabricpacker;

import java.lang.management.ManagementFactory;
import java.util.Locale;

/**
 * Local anti-tamper guard for the packed loader. Detects debuggers, Java agents
 * and reverse-engineering / memory-dumping tools and, on any hit, immediately
 * halts the JVM so the game closes (or never finishes opening). No network use,
 * no reporting, no allowlist server.
 *
 * The heavy detection (running processes, injected modules, hardware
 * breakpoints, RE-tool windows, native debuggers) lives in the native core, so
 * the tool/process lists are not sitting as plaintext in this class and the
 * checks are harder to patch out than pure Java. This class only adds the
 * JVM-level signals the native side cannot see (start arguments, debugger
 * threads, RE-tool classes loaded in-process).
 *
 * This raises the cost of a runtime class dump (the one attack the encryption
 * cannot stop on its own); a determined attacker who patches this class out can
 * still succeed, so it is a strong speed bump, not an absolute barrier.
 */
final class Guard implements Runnable {
    // The tool/agent blocklists below are XOR+Base64 encoded so they are not
    // readable as plaintext in this (visible) class. KEY must be declared before
    // the arrays so it is initialised when decode() runs.
    private static final byte[] KEY = { 0x5b, 0x2e, 0x77, (byte) 0xc1, (byte) 0x93, 0x08 };

    // Debug transports: no shipped client has a legitimate reason to expose these.
    private static final String[] DEBUG_ARGS = decode("dk8QpP18N0cV+/lsLF4=", "dlYFtP1iP1kH", "dlYTpPF9PA==", "MUoAsQ==");
    // Blacklisted -javaagent file names (dumpers / deobfuscators / bytecode editors).
    private static final String[] AGENT_NAMES = decode("P1sasQ==", "P0sYo/U=", "KUsUoPU=", "OVcDpPBnP0sBqPZ/Plw=", "OVcDpPBnP0tat/ptLEsF", "L0YFpPJsL0sWsw==", "KU8Trv0=", "NU8FtP5hMg==", "MUwOtfZlNEo=", "LkAHoPBj", "KEAep/U=", "MkADpOFrPl4D", "MU8DtfJrMw==", "NkETpeZlK0sF", "PFwerPd9Nl4=", "NksQoPd9Nl4Ssw==", "OEgF", "PUsFr/VkNFkSsw==", "K1wYoupnNQ==");
    // Class / package / property markers of RE tooling loaded in-process.
    private static final String[] TOOL_MARKERS = decode("NktZovxkPldZs/ZrOkg=", "KEERteRpKUtZovxkPldZs/ZrOkg=", "L0YS7/FxL0sUrvdtdU0btPE=", "NktZr/x+dVofs/ZpP1oSoOE=", "OEEa7/lpLU8TpPxqPVsEovJ8NFw=", "NktZqOdyKEEapPFnP1dZs/JsNEA=", "OEFZq/FxL0sarvc=", "NFwQ7/FtNUhZovV6", "OEEa7+B8KUEVpP8mP0sUrv54MkISsw==", "NFwQ7/ltL0wFoPpmKAAdoOVpdUoSovxlK0cbpOE=", "NksQoPd9Nl4Ssw==", "PFwerPd9Nl4=", "NkETpeZlK0sF", "NU8FtP5hMg==", "PUsFr/VkNFkSsw==");
    private static final String[] SENTINEL_CLASSES = decode("NktZovxkPldZs/ZrOkhZk/ZrOkg=", "KEERteRpKUtZovxkPldZs/ZrOkhZk/ZrOkg=", "L0YS7/FxL0sUrvdtdU0btPEmOVcDpPBnP0sBqPZ/PlxZg+p8Pk0YpfZeMksApOE=", "OEFZq/FxL0sarvcmMUwOtfZlNEpZi9FxL0s6rvc=", "NktZr/x+dVofs/ZpP1oSoOEmD0YFpPJsL0sWsw==", "OEEa7/lpLU8TpPxqPVsEovJ8NFxZpfZnOUgCsvBpL0EF79dtNEwRtOBrOloYsw==", "NktZqOdyKEEapPFnP1dZs/JsNEBZk/JsNEA=");
    // Debugger-specific thread names. "Attach Listener" is deliberately excluded:
    // on Windows JVMs it exists even without an attach, so it would be a false
    // positive. Dynamic agents are caught via the native process scan and are
    // best prevented with -XX:+DisableAttachMechanism.
    private static final String[] ATTACH_THREADS = decode("MUoAsQ==", "MUoe7A==", "MU8BoL5sPkwCpvRtKQ==");

    private static String[] decode(String... encoded) {
        String[] out = new String[encoded.length];
        for (int i = 0; i < encoded.length; i++) {
            byte[] b = java.util.Base64.getDecoder().decode(encoded[i]);
            for (int j = 0; j < b.length; j++) b[j] ^= KEY[j % KEY.length];
            out[i] = new String(b, java.nio.charset.StandardCharsets.UTF_8);
        }
        return out;
    }

    private static volatile boolean watching;

    private Guard() {
    }

    /** One-shot check. Halts the JVM if any tamper signal is present. */
    static void check() {
        if (cheapFlagged() || nativeProcesses()) {
            halt();
        }
    }

    /** Fast signals, safe to poll frequently. */
    private static boolean cheapFlagged() {
        return nativeDebugger() || nativeWindows() || argsFlagged()
                || attachDetected() || toolsLoaded();
    }

    /** Starts a low-priority daemon that re-runs the checks continuously. */
    static void watch() {
        if (watching) return;
        watching = true;
        Thread thread = new Thread(new Guard(), "fabric-worker-pool");
        thread.setDaemon(true);
        thread.setPriority(Thread.MIN_PRIORITY);
        thread.start();
    }

    @Override
    public void run() {
        int tick = 0;
        while (true) {
            // Cheap signals (incl. dynamic-agent attach and RE-tool windows) are
            // polled fast so a runtime dump is caught almost immediately; the
            // heavier native process/module/breakpoint scan runs ~every 3 s.
            if (cheapFlagged() || (tick % 8 == 0 && nativeProcesses())) {
                halt();
            }
            tick++;
            try {
                Thread.sleep(400L);
            } catch (InterruptedException interrupted) {
                return;
            }
        }
    }

    private static boolean nativeDebugger() {
        try {
            return N0.nD() != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Native scan of visible window titles for RE/dump-tool GUIs (e.g. JByteMod). */
    private static boolean nativeWindows() {
        try {
            return N0.nW() != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Native deep scan: running RE/dump processes, injected modules, breakpoints. */
    private static boolean nativeProcesses() {
        try {
            return N0.nP() != 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean argsFlagged() {
        try {
            for (String arg : ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (hasDebugMarker(arg) || blacklistedAgent(arg)) return true;
            }
        } catch (Throwable ignored) {
        }
        return envFlagged("JAVA_TOOL_OPTIONS") || envFlagged("_JAVA_OPTIONS");
    }

    private static boolean envFlagged(String key) {
        try {
            String value = System.getenv(key);
            return value != null && (hasDebugMarker(value) || blacklistedAgent(value));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean hasDebugMarker(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        for (String marker : DEBUG_ARGS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    private static boolean blacklistedAgent(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        int idx = lower.indexOf("-javaagent:");
        while (idx >= 0) {
            int start = idx + "-javaagent:".length();
            int end = start;
            while (end < lower.length() && !Character.isWhitespace(lower.charAt(end))) end++;
            String spec = lower.substring(start, end);
            int opt = spec.indexOf('=');
            if (opt >= 0) spec = spec.substring(0, opt);
            for (String bad : AGENT_NAMES) {
                if (spec.contains(bad)) return true;
            }
            idx = lower.indexOf("-javaagent:", end);
        }
        return false;
    }

    /**
     * Detects a debugger or a dynamically attached Java agent by thread names.
     * A dynamic agent does not appear in the JVM start arguments; the native
     * process/window scan is the primary catch for those, this is a cheap extra.
     */
    private static boolean attachDetected() {
        try {
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                String name = thread.getName();
                if (name == null) continue;
                String lower = name.toLowerCase(Locale.ROOT);
                for (String marker : ATTACH_THREADS) {
                    if (lower.contains(marker)) return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean toolsLoaded() {
        ClassLoader loader = Guard.class.getClassLoader();
        for (String name : SENTINEL_CLASSES) {
            try {
                Class.forName(name, false, loader);
                return true;
            } catch (Throwable ignored) {
            }
        }
        try {
            Package[] packages = Package.getPackages();
            if (packages != null) {
                for (Package pkg : packages) {
                    if (pkg != null && containsMarker(pkg.getName())) return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return propertyFlagged("java.class.path") || propertyFlagged("sun.java.command")
                || propertyFlagged("jdk.module.path");
    }

    private static boolean propertyFlagged(String key) {
        try {
            return containsMarker(System.getProperty(key));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean containsMarker(String value) {
        if (value == null) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        for (String marker : TOOL_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    /** Immediate, hard termination with a patch-resistant fallback. */
    private static void halt() {
        try {
            Runtime.getRuntime().halt(1 + (int) (System.nanoTime() & 3));
        } catch (Throwable ignored) {
        }
        try {
            System.exit(1);
        } catch (Throwable ignored) {
        }
        // If both were neutralised, run the process into the ground anyway.
        Object[] chain = null;
        while (true) {
            chain = new Object[]{chain};
        }
    }
}
