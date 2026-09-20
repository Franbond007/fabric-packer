package fabricpacker;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Runs the local ProGuard optimizer over loader bytecode only.
 *
 * The payload is never passed to this step. Names are kept because the packer
 * already generated the per-build names and rewrote their references. Keeping
 * names also prevents an optimizer from breaking Fabric metadata or JVM owner
 * relationships while still allowing bytecode optimization and structural
 * cleanup. This is an offline hardening step, not a complete decompiler or
 * memory extraction defense.
 */
final class LoaderOptimizer {
    private static final String[] TOOLS = {
            "proguard-base-7.7.0.jar",
            "proguard-core-9.1.10.jar",
            "kotlin-stdlib-2.1.0.jar",
            "gson-2.11.0.jar",
            "json-20231013.jar",
            "log4j-api-2.24.2.jar",
            "log4j-core-2.24.2.jar"
    };

    private LoaderOptimizer() {
    }

    static Map<String, byte[]> optimize(Map<String, byte[]> input) throws IOException {
        return optimize(input, (String) null);
    }

    static Map<String, byte[]> optimize(Map<String, byte[]> input, String nonOptimizedClass) throws IOException {
        Set<String> protectedClasses = nonOptimizedClass == null
                ? Set.of() : Set.of(nonOptimizedClass);
        return optimize(input, protectedClasses);
    }

    static Map<String, byte[]> optimize(Map<String, byte[]> input, Set<String> nonOptimizedClasses)
            throws IOException {
        if (input.isEmpty()) return new LinkedHashMap<>();
        Path tools = locateTools();
        Path temp = Files.createTempDirectory("fabricpacker-loader-opt-");
        Path source = temp.resolve("loader-in.jar");
        Path target = temp.resolve("loader-out.jar");
        Path config = temp.resolve("proguard.conf");
        try {
            writeJar(source, input);
            Files.writeString(config, configuration(source, target, input, nonOptimizedClasses), StandardCharsets.UTF_8);
            List<String> command = new ArrayList<>();
            command.add(javaExecutable());
            command.add("-cp");
            command.add(classpath(tools));
            command.add("proguard.ProGuard");
            command.add("@" + config);
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            String diagnostics;
            try (InputStream in = process.getInputStream()) {
                diagnostics = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
            int exit;
            try {
                exit = process.waitFor();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("ProGuard optimizer interrupted", interrupted);
            }
            if (exit != 0 || !Files.isRegularFile(target)) {
                throw new IOException("Offline loader optimizer failed (exit " + exit + "): " + diagnostics);
            }
            Map<String, byte[]> result = readClasses(target);
            if (!result.keySet().equals(input.keySet())) {
                wipe(result);
                throw new IOException("Offline loader optimizer changed loader class set");
            }
            return result;
        } finally {
            deleteTree(temp);
        }
    }

    private static Path locateTools() throws IOException {
        List<Path> candidates = new ArrayList<>();
        String configured = System.getProperty("fabricpacker.proguard.tools");
        if (configured != null && !configured.isBlank()) candidates.add(Path.of(configured));
        candidates.add(Path.of("tools"));
        String classPath = System.getProperty("java.class.path", "");
        for (String item : classPath.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
            Path path = Path.of(item).toAbsolutePath().normalize();
            if (Files.isRegularFile(path)) candidates.add(path.getParent().resolve("tools"));
        }
        for (Path candidate : candidates) {
            Path absolute = candidate.toAbsolutePath().normalize();
            boolean complete = true;
            for (String tool : TOOLS) complete &= Files.isRegularFile(absolute.resolve(tool));
            if (complete) return absolute;
        }
        throw new IOException("Offline ProGuard tools missing. Expected tools next to the packer or -Dfabricpacker.proguard.tools=<dir>");
    }

    private static String classpath(Path tools) {
        StringBuilder result = new StringBuilder();
        for (String tool : TOOLS) {
            if (result.length() > 0) result.append(java.io.File.pathSeparatorChar);
            result.append(tools.resolve(tool));
        }
        return result.toString();
    }

    private static String javaExecutable() {
        Path javaPath = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win") ? "java.exe" : "java");
        return javaPath.toString();
    }

    private static String configuration(Path source, Path target, Map<String, byte[]> input,
            Set<String> nonOptimizedClasses) {
        StringBuilder text = new StringBuilder();
        text.append("-injars '").append(source).append("'\n");
        text.append("-outjars '").append(target).append("'\n");
        text.append("-dontshrink\n-dontnote\n-dontwarn **\n-ignorewarnings\n");
        // Do not allow access tightening: generated key-part classes call each
        // other through package-private methods in the same loader package.
        text.append("-optimizationpasses 1\n");
        text.append("-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,");
        text.append("RuntimeVisibleParameterAnnotations,RuntimeInvisibleParameterAnnotations,");
        text.append("AnnotationDefault,Signature,InnerClasses,EnclosingMethod,NestHost,NestMembers,");
        text.append("Record,PermittedSubclasses,Exceptions,BootstrapMethods,MethodParameters,StackMapTable\n");
        // Java records rely on the JVM's ObjectMethods bootstrap for the
        // compiler-generated equals/hashCode/toString methods. Keep record
        // names, members and bytecode untouched. This rule is relevant to
        // loader records such as its in-memory entry descriptor; the payload
        // itself is never passed to ProGuard by this class.
        text.append("-keep class * extends java.lang.Record { *; }\n");
        Path javaBase = Path.of(System.getProperty("java.home"), "jmods", "java.base.jmod");
        if (Files.isRegularFile(javaBase)) text.append("-libraryjars '").append(javaBase).append("'\n");
        for (String path : input.keySet()) {
            String name = path.substring(0, path.length() - ".class".length()).replace('/', '.');
            if (nonOptimizedClasses.contains(path)) {
                // Fabric invokes this interface method reflectively through its entrypoint API.
                text.append("-keep class ").append(name).append(" { public void onPreLaunch(); }\n");
            } else {
                text.append("-keep,allowoptimization class ").append(name).append(" { *; }\n");
            }
        }
        return text.toString();
    }

    private static void writeJar(Path path, Map<String, byte[]> entries) throws IOException {
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(path))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                JarEntry target = new JarEntry(entry.getKey());
                target.setTime(0L);
                jar.putNextEntry(target);
                jar.write(entry.getValue());
                jar.closeEntry();
            }
        }
    }

    private static Map<String, byte[]> readClasses(Path path) throws IOException {
        Map<String, byte[]> result = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(path.toFile())) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                    result.put(entry.getName(), jar.getInputStream(entry).readAllBytes());
                }
            }
        }
        return result;
    }

    private static void wipe(Map<String, byte[]> values) {
        for (byte[] value : values.values()) java.util.Arrays.fill(value, (byte) 0);
    }

    private static void deleteTree(Path root) {
        try {
            if (!Files.exists(root)) return;
            try (var paths = Files.walk(root)) {
                paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (IOException ignored) { }
                });
            }
        } catch (IOException ignored) {
        }
    }
}
