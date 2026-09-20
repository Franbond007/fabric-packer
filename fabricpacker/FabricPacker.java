package fabricpacker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Packs remapped Fabric classes and resources into one authenticated memory container. */
public final class FabricPacker {
    private static final String FABRIC_MOD = "fabric.mod.json";
    private static final String PAYLOAD_RESOURCE_PREFIX = "fabricpacker/p";
    private static final String SIGNATURE_RESOURCE_PREFIX = "fabricpacker/s";
    private static final String WATERMARK_RESOURCE_PREFIX = "fabricpacker/w";
    private static final String[] RUNTIME_CLASSES = {
            "fabricpacker/FabricBootstrap.class",
            "fabricpacker/PackedClassLoader.class",
            "fabricpacker/PackedClassLoader$MemoryUrlHandler.class",
            "fabricpacker/PackedClassLoader$MemoryURLConnection.class",
            "fabricpacker/PackedClassLoader$WipingInputStream.class",
            "fabricpacker/PackedClassLoader$Entry.class",
            "fabricpacker/Guard.class",
            "fabricpacker/N0.class",
            "fabricpacker/A0.class",
            "fabricpacker/A1.class",
            "fabricpacker/A2.class"
    };
    /** Base resource path of the embedded native crypto core (per-OS extension appended). */
    private static final String NATIVE_RESOURCE = "fabricpacker/pkcore";
    private static final int SALT_LENGTH = 32;
    private static final int INFO_LENGTH = 32;
    /**
     * Build-side copy of the native key-mask IKM. This constant MUST match
     * BAKED_IKM in native/pk_sha1.h; the per-build native self-test decrypts a
     * real blob through the actual DLL and fails the build if the two drift.
     * It lives only in the build tool - the packed mod ships nothing but
     * (material = key XOR HKDF(IKM, salt, info)), which is useless without the
     * native binary. Rotate together with the native core for a release.
     */
    private static final byte[] BAKED_IKM = {
            (byte) 0x18, (byte) 0x9a, (byte) 0x66, (byte) 0x84, (byte) 0x72, (byte) 0x27, (byte) 0x48, (byte) 0xae,
            (byte) 0xce, (byte) 0x7e, (byte) 0x57, (byte) 0x2d, (byte) 0x16, (byte) 0xfb, (byte) 0x7b, (byte) 0x22,
            (byte) 0x48, (byte) 0x4d, (byte) 0x5f, (byte) 0x08, (byte) 0xcb, (byte) 0x19, (byte) 0xcb, (byte) 0xa4,
            (byte) 0x01, (byte) 0x34, (byte) 0x87, (byte) 0x6b, (byte) 0x2c, (byte) 0xdf, (byte) 0x8b, (byte) 0xaf
    };
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int HEADER_LENGTH = 4 + 2 + NONCE_LENGTH + 4;
    private static final int ENTRY_TYPE_CLASS = 1;
    private static final int ENTRY_TYPE_RESOURCE = 2;
    private static final int PADDING_BUCKET = 1024;
    private static final int KEY_WORDS = 8;
    private static final String[] LEAK_TERMS = {
            "Freecam", "NameProtect", "StorageESP", "ChunkFinder", "AmethystESP",
            "Protection", "Hud", "fabricpacker.key", "javax/crypto/Cipher",
            "GCMParameterSpec", "SecretKeySpec", "decrypt", "openCipher", "reconstruct"
    };

    private FabricPacker() {
    }

    private static final String USAGE = """
            Verwendung: java -jar fabric-packer.jar <remapped.jar> [config.json] [Optionen]

            Optionen:
              --output <pfad>      Ausgabe-JAR (Standard: packed-fabric.jar neben der Eingabe)
              --exclude <pfad>     Klasse oder Ressource zusaetzlich sichtbar halten (mehrfach moeglich)
              --watermark <id>     Kunden-Wasserzeichen statt Zufall (Leak-Rueckverfolgung)
              --compression <1-9>  zlib-Kompressionsstufe (Standard: 9)
              --parallel <1-32>    Parallele Verschluesselung der Eintraege (Standard: CPU-Kerne)
              --quiet              Nur Fehler ausgeben
              --verbose            Stacktraces bei Fehlern zeigen
              --help               Diese Hilfe anzeigen

            config.json unterstuetzt: exclude (classes/resources), leakTerms,
            compression (1-9) und parallelism (1-32). Siehe README.md.
            """;

    private static boolean QUIET;

    /** Per-thread CSPRNG, reused across blobs to avoid repeated seeding in the hot path. */
    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public static void main(String[] args) {
        Options options;
        try {
            options = parseOptions(args);
        } catch (IllegalArgumentException usage) {
            System.err.println(usage.getMessage());
            System.err.println();
            System.err.println(USAGE);
            System.exit(2);
            return;
        }
        if (options.help()) {
            System.out.println(USAGE);
            return;
        }
        QUIET = options.quiet();
        try {
            Path input = options.input();
            requireFile(input, "Input JAR");
            if (options.config() != null) requireFile(options.config(), "Config");
            PackConfig config = options.config() == null ? readConfig("{}")
                    : readConfig(Files.readString(options.config()));
            Set<String> excludes = new LinkedHashSet<>(config.excludes());
            excludes.addAll(options.excludes());
            int compression = options.compression() == null ? config.compression() : options.compression();
            int parallelism = options.parallelism() == null ? config.parallelism() : options.parallelism();
            List<String> leakTerms = new ArrayList<>(config.leakTerms());
            Path output = options.output() == null ? input.resolveSibling("packed-fabric.jar")
                    : options.output().toAbsolutePath().normalize();
            if (input.equals(output)) throw new IOException("Input and output JAR must be different files");
            pack(input, output, excludes, leakTerms, options.watermark(), compression, parallelism);
            report("Created: " + output);
        } catch (Exception failure) {
            if (options.verbose()) {
                failure.printStackTrace();
            } else {
                String message = failure.getMessage();
                System.err.println(message == null ? "Fehler: " + failure.getClass().getName()
                        : "Fehler: " + message);
                System.err.println("Weitere Details mit --verbose");
            }
            System.exit(1);
        }
    }

    record Options(Path input, Path config, Path output, List<String> excludes, String watermark,
            Integer compression, Integer parallelism, boolean quiet, boolean verbose, boolean help) {
    }

    private static Options parseOptions(String[] args) {
        Path input = null;
        Path config = null;
        Path output = null;
        List<String> excludes = new ArrayList<>();
        String watermark = null;
        Integer compression = null;
        Integer parallelism = null;
        boolean quiet = false;
        boolean verbose = false;
        boolean help = false;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--help", "-h" -> help = true;
                case "--output", "-o" -> output = Path.of(requireValue(arg, args, ++i));
                case "--exclude" -> excludes.add(requireValue(arg, args, ++i));
                case "--watermark" -> watermark = requireValue(arg, args, ++i);
                case "--compression" -> compression = parseRange(arg, requireValue(arg, args, ++i), 1, 9);
                case "--parallel" -> parallelism = parseRange(arg, requireValue(arg, args, ++i), 1, 32);
                case "--quiet", "-q" -> quiet = true;
                case "--verbose" -> verbose = true;
                default -> {
                    if (arg.startsWith("-")) throw new IllegalArgumentException("Unbekannte Option: " + arg);
                    if (input == null) input = Path.of(arg).toAbsolutePath().normalize();
                    else if (config == null) config = Path.of(arg).toAbsolutePath().normalize();
                    else throw new IllegalArgumentException("Unerwartetes Argument: " + arg);
                }
            }
        }
        if (help) {
            return new Options(null, null, null, List.copyOf(excludes), watermark, compression, parallelism,
                    quiet, verbose, true);
        }
        if (input == null) throw new IllegalArgumentException("Eingabe-JAR fehlt");
        if (config == null) {
            Path defaultConfig = Path.of("pack-config.json");
            if (Files.isRegularFile(defaultConfig)) config = defaultConfig.toAbsolutePath().normalize();
        }
        return new Options(input, config, output, List.copyOf(excludes), watermark, compression, parallelism,
                quiet, verbose, false);
    }

    private static String requireValue(String option, String[] args, int index) {
        if (index >= args.length) throw new IllegalArgumentException("Option " + option + " benoetigt einen Wert");
        return args[index];
    }

    private static int parseRange(String option, String value, int min, int max) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < min || parsed > max) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException(option + " muss zwischen " + min + " und " + max + " liegen: " + value);
        }
    }

    static void report(String message) {
        if (!QUIET) System.out.println(message);
    }

    private static void pack(Path input, Path output, Set<String> configuredExcludes,
            List<String> extraLeakTerms, String watermarkCustomer, int compressionLevel, int parallelism)
            throws Exception {
        Map<String, byte[]> inputEntries = readEntries(input);
        Map<String, byte[]> outputEntries = new LinkedHashMap<>();
        Map<String, byte[]> protectedEntries = new LinkedHashMap<>();
        Map<String, String> exclusions = new LinkedHashMap<>();
        byte[] previousOutputHash = Files.isRegularFile(output) ? sha256File(output) : null;
        SigningMaterial signing = loadSigningMaterial(output);
        byte[] publicKey = signing.publicEncoded;
        byte[] privateEncoded = signing.privateEncoded;
        byte[] key = generateKey();
        byte[] salt = randomBytes(SALT_LENGTH);
        byte[] info = randomBytes(INFO_LENGTH);
        byte[] mask = hkdfMask(salt, info);
        byte[] material = xor(key, mask);
        Map<String, Path> nativeCores = locateNativeCores();
        Path selfTestCore = nativeCores.get(currentOsExt());
        if (selfTestCore == null) {
            throw new IOException("Native core for the build OS is missing: expected packcore"
                    + currentOsExt() + " in native/ (build it with native/build-native.*)");
        }
        report("Embedding native cores: " + String.join(", ", nativeCores.keySet()));
        byte[] signature = randomBytes(4);
        byte[] indexTag = randomBytes(16);
        SecureRandom buildRandom = new SecureRandom();
        String payloadResource = randomPayloadResource(buildRandom);
        String signatureResource = randomSignatureResource(buildRandom);
        String watermarkResource = randomWatermarkResource(buildRandom);
        byte[] watermark = buildWatermark(watermarkCustomer);
        int version = buildRandom.nextInt(65535) + 1;
        byte[] payload = null;
        byte[] signedManifest = null;
        try {
            byte[] fabricMod = inputEntries.get(FABRIC_MOD);
            if (fabricMod == null) throw new IOException("Input JAR has no fabric.mod.json");
            Map<String, Object> metadata = SimpleJson.object(
                    SimpleJson.parse(new String(fabricMod, StandardCharsets.UTF_8), FABRIC_MOD),
                    FABRIC_MOD + " must contain a JSON object");

            Set<String> excluded = new LinkedHashSet<>(configuredExcludes);
            excluded.add("fabricpacker.FabricBootstrap");
            excluded.add("fabricpacker.PackedClassLoader");
            excluded.add("net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint");
            collectEntrypointExcludes(metadata, excluded);
            collectMixinExcludes(metadata, inputEntries, excluded);
            Map<String, String> classNames = runtimeClassNames();
            Set<String> loaderOwners = new LinkedHashSet<>(classNames.keySet());
            Map<String, byte[]> runtimeSources = new LinkedHashMap<>();
            for (String runtimeClass : RUNTIME_CLASSES) {
                if (runtimeClass.endsWith("/A0.class") || runtimeClass.endsWith("/A1.class")
                        || runtimeClass.endsWith("/A2.class")) continue;
                String owner = runtimeClass.substring(0, runtimeClass.length() - ".class".length());
                runtimeSources.put(owner, readOwnResource(runtimeClass));
            }
            Map<String, String> methodNames = runtimeMethodNames(runtimeSources);
            Map<String, String> fieldNames = runtimeFieldNames(runtimeSources);

            for (Map.Entry<String, byte[]> entry : inputEntries.entrySet()) {
                String path = entry.getKey();
                rejectReservedInput(path);
                if (path.equalsIgnoreCase("META-INF/MANIFEST.MF") || isSignature(path)) continue;
                if (isRuntimeClass(path)) continue;
                if (path.equals(FABRIC_MOD)) {
                    outputEntries.put(path, SimpleJson.write(withPreLaunch(metadata, classNames))
                            .getBytes(StandardCharsets.UTF_8));
                    continue;
                }
                if (path.endsWith(".class") && isExcludedClass(path, excluded)) {
                    outputEntries.put(path, entry.getValue());
                    exclusions.put(path.substring(0, path.length() - 6).replace('/', '.'),
                            exclusionReason(path, excluded));
                } else if (path.endsWith(".class")) {
                    protectedEntries.put(path, entry.getValue());
                } else if (shouldRemainPlain(path, excluded)) {
                    outputEntries.put(path, rewriteVisibleMetadata(path, entry.getValue(), classNames));
                } else {
                    protectedEntries.put(path, entry.getValue());
                }
            }
            if (protectedEntries.isEmpty()) throw new IOException("No classes or resources selected for packing");
            for (String value : excluded) exclusions.putIfAbsent(value, exclusionReasonFor(value));

            Map<String, byte[]> transformedRuntime = new LinkedHashMap<>();
            for (Map.Entry<String, byte[]> source : runtimeSources.entrySet()) {
                byte[] transformed = rewriteClass(source.getValue(), loaderOwners,
                        classNames, methodNames, fieldNames);
                transformedRuntime.put(remapClassPath(source.getKey() + ".class", classNames), transformed);
            }
            runLoaderRewriteSelfTests(runtimeSources, loaderOwners, classNames, methodNames, fieldNames);
            wipeMap(runtimeSources);
            String entrypointClass = remapClassPath("fabricpacker/FabricBootstrap.class", classNames);
            Map<String, byte[]> optimizedRuntime = LoaderOptimizer.optimize(transformedRuntime, entrypointClass);
            wipeMap(transformedRuntime);
            transformedRuntime = optimizedRuntime;
            Map<String, byte[]> integrity = new LinkedHashMap<>();
            for (Map.Entry<String, byte[]> runtime : transformedRuntime.entrySet()) {
                integrity.put(runtime.getKey(), sha256(runtime.getValue()));
            }
            Map<String, byte[]> runtimeParts = generateRuntimeParts(
                    material, salt, info, integrity, signature, indexTag, payloadResource, signatureResource,
                    publicKey, version, classNames, loaderOwners, methodNames, fieldNames);
            Map<String, byte[]> finalRuntime = new LinkedHashMap<>(optimizedRuntime);
            for (Map.Entry<String, byte[]> runtime : runtimeParts.entrySet()) {
                String finalPath = remapClassPath(runtime.getKey(), classNames);
                byte[] transformed = rewriteClass(runtime.getValue(), loaderOwners,
                        classNames, methodNames, fieldNames);
                finalRuntime.put(finalPath, transformed);
                outputEntries.put(finalPath, transformed);
            }
            for (Map.Entry<String, byte[]> runtime : transformedRuntime.entrySet()) {
                outputEntries.put(runtime.getKey(), runtime.getValue());
            }
            validateLoaderReferences(finalRuntime);
            wipeMap(runtimeParts);
            wipeHashMap(integrity);

            payload = buildContainer(protectedEntries, exclusions, key, signature, indexTag, version,
                    compressionLevel, parallelism);
            runPayloadSelfTests(payload, key, signature, indexTag, version);
            runNativeSelfTest(payload, material, salt, info, signature, indexTag, version,
                    selfTestCore, key);
            outputEntries.put(payloadResource, payload);
            outputEntries.put(watermarkResource, watermark);
            for (Map.Entry<String, Path> core : nativeCores.entrySet()) {
                outputEntries.put(NATIVE_RESOURCE + core.getKey(), Files.readAllBytes(core.getValue()));
            }
            signedManifest = SignatureSupport.create(outputEntries, payloadResource, signing.privateKey);
            outputEntries.put(signatureResource, signedManifest);
            writeJar(output, outputEntries);
            verifyOutputJar(output, payloadResource, signatureResource, protectedEntries,
                    key, publicKey, privateEncoded, extraLeakTerms, NATIVE_RESOURCE);
            SignatureSupport.SelfTestResult signatureTests = SignatureSupport.selfTest(
                    readEntries(output), signatureResource, publicKey, payloadResource);
            report("Ed25519 tests: valid=PASS payload=" + signatureTests.payloadRejected()
                    + " loader=" + signatureTests.loaderRejected() + " index=" + signatureTests.indexRejected()
                    + " missing=" + signatureTests.missingRejected() + " wrongPublicKey="
                    + signatureTests.wrongKeyRejected());
            verifyOutputDirectory(output.getParent(), input, output);
            if (previousOutputHash != null) {
                byte[] currentOutputHash = sha256File(output);
                try {
                    if (MessageDigest.isEqual(previousOutputHash, currentOutputHash)) {
                        throw new IOException("Build randomness check failed: two consecutive builds are identical");
                    }
                } finally {
                    wipe(currentOutputHash);
                }
            }
        } finally {
            wipe(key);
            wipe(salt);
            wipe(info);
            wipe(mask);
            wipe(material);
            wipe(signature);
            wipe(indexTag);
            wipe(watermark);
            wipe(payload);
            wipe(signedManifest);
            wipe(publicKey);
            wipe(privateEncoded);
            wipe(previousOutputHash);
            wipeMap(inputEntries);
            wipeMap(protectedEntries);
            wipeMap(outputEntries);
        }
    }

    private static byte[] buildContainer(Map<String, byte[]> clearEntries,
            Map<String, String> exclusions, byte[] key, byte[] signature, byte[] indexTag,
            int version, int compressionLevel, int parallelism) throws Exception {
        List<Blob> blobs = parallelBlobs(clearEntries, key, signature, indexTag, version,
                compressionLevel, parallelism);
        Collections.shuffle(blobs, new SecureRandom());
        SecureRandom random = new SecureRandom();

        int indexClearLength = 4 + 4;
        for (Blob blob : blobs) {
            indexClearLength += 4 + blob.path.getBytes(StandardCharsets.UTF_8).length
                    + 1 + 8 + 4 + 4 + 4 + 4 + HASH_LENGTH;
        }
        for (Map.Entry<String, String> exclusion : exclusions.entrySet()) {
            indexClearLength += 4 + exclusion.getKey().getBytes(StandardCharsets.UTF_8).length;
            indexClearLength += 4 + exclusion.getValue().getBytes(StandardCharsets.UTF_8).length;
        }
        int indexCipherLength = indexClearLength + TAG_LENGTH;
        long offset = HEADER_LENGTH + indexCipherLength;
        for (int i = 0; i < blobs.size(); i++) {
            Blob old = blobs.get(i);
            blobs.set(i, new Blob(old.path, old.type, old.clearLength, old.compressedLength,
                    old.paddingLength, old.hash, old.blob, offset));
            offset += old.blob.length;
        }

        byte[] indexClear = null;
        byte[] indexNonce = new byte[NONCE_LENGTH];
        random.nextBytes(indexNonce);
        byte[] indexCipher = null;
        try {
            indexClear = serializeIndex(blobs, exclusions);
            if (indexClear.length != indexClearLength) {
                throw new IOException("Packed index size calculation mismatch");
            }
            indexCipher = encrypt(indexClear, key, indexNonce, indexTag);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.toIntExact(offset));
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(signature);
            output.writeShort(version);
            output.write(indexNonce);
            output.writeInt(indexCipher.length);
            output.write(indexCipher);
            for (Blob blob : blobs) output.write(blob.blob);
            output.flush();
            report("Payload profile: order=" + profileFingerprint(blobs, false)
                    + " padding=" + profileFingerprint(blobs, true));
            return bytes.toByteArray();
        } finally {
            wipe(indexClear);
            wipe(indexNonce);
            wipe(indexCipher);
            for (Blob blob : blobs) {
                wipe(blob.hash);
                wipe(blob.blob);
            }
        }
    }

    private static List<Blob> parallelBlobs(Map<String, byte[]> clearEntries, byte[] key, byte[] signature,
            byte[] indexTag, int version, int compressionLevel, int parallelism) throws Exception {
        List<Blob> blobs = new ArrayList<>(clearEntries.size());
        int threads = Math.max(1, Math.min(parallelism, clearEntries.size()));
        if (threads == 1) {
            for (Map.Entry<String, byte[]> entry : clearEntries.entrySet()) {
                blobs.add(buildBlob(entry.getKey(), entry.getValue(), key, signature, indexTag, version,
                        compressionLevel));
            }
            return blobs;
        }
        ExecutorService pool = Executors.newFixedThreadPool(threads, task -> {
            Thread thread = new Thread(task, "fabric-packer-blob");
            thread.setDaemon(true);
            return thread;
        });
        try {
            List<Future<Blob>> futures = new ArrayList<>(clearEntries.size());
            for (Map.Entry<String, byte[]> entry : clearEntries.entrySet()) {
                futures.add(pool.submit(() -> buildBlob(entry.getKey(), entry.getValue(), key, signature,
                        indexTag, version, compressionLevel)));
            }
            for (Future<Blob> future : futures) {
                try {
                    blobs.add(future.get());
                } catch (ExecutionException failed) {
                    Throwable cause = failed.getCause();
                    if (cause instanceof Exception exception) throw exception;
                    throw new IOException("Entry encryption failed", cause);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Entry encryption interrupted", interrupted);
                }
            }
            return blobs;
        } finally {
            pool.shutdownNow();
        }
    }

    private static Blob buildBlob(String path, byte[] clear, byte[] key, byte[] signature, byte[] indexTag,
            int version, int compressionLevel) throws Exception {
        SecureRandom random = RANDOM.get();
        byte[] hash = sha256(clear);
        byte[] compressed = compress(clear, compressionLevel);
        int paddingLength = ((PADDING_BUCKET - (compressed.length % PADDING_BUCKET)) % PADDING_BUCKET)
                + 1 + random.nextInt(PADDING_BUCKET);
        byte[] padded = new byte[compressed.length + paddingLength];
        System.arraycopy(compressed, 0, padded, 0, compressed.length);
        if (paddingLength > 0) {
            byte[] padding = new byte[paddingLength];
            random.nextBytes(padding);
            System.arraycopy(padding, 0, padded, compressed.length, paddingLength);
            wipe(padding);
        }
        wipe(compressed);
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        int type = path.endsWith(".class") ? ENTRY_TYPE_CLASS : ENTRY_TYPE_RESOURCE;
        byte[] aad = tagData(path, type, clear.length, compressedLength(padded, paddingLength),
                paddingLength, hash, signature, indexTag, version);
        byte[] cipher = null;
        try {
            cipher = encrypt(padded, key, nonce, aad);
            byte[] blob = new byte[NONCE_LENGTH + cipher.length];
            System.arraycopy(nonce, 0, blob, 0, NONCE_LENGTH);
            System.arraycopy(cipher, 0, blob, NONCE_LENGTH, cipher.length);
            return new Blob(path, type, clear.length, padded.length - paddingLength,
                    paddingLength, hash, blob, 0L);
        } finally {
            wipe(aad);
            wipe(cipher);
            wipe(padded);
            wipe(nonce);
        }
    }

    private static String profileFingerprint(List<Blob> blobs, boolean paddingOnly) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        for (Blob blob : blobs) {
            byte[] pathHash = sha256(blob.path.getBytes(StandardCharsets.UTF_8));
            output.write(pathHash, 0, 8);
            output.writeInt(blob.type);
            output.writeInt(paddingOnly ? blob.paddingLength : blob.blob.length);
            wipe(pathHash);
        }
        output.flush();
        byte[] digest = sha256(bytes.toByteArray());
        try {
            StringBuilder result = new StringBuilder(16);
            for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i] & 0xff));
            return result.toString();
        } finally {
            wipe(digest);
        }
    }

    private static void runPayloadSelfTests(byte[] payload, byte[] key, byte[] signature,
            byte[] indexTag, int version) throws Exception {
        List<TestBlob> blobs = readTestIndex(payload, key, indexTag);
        TestBlob classBlob = blobs.stream().filter(blob -> blob.type == ENTRY_TYPE_CLASS).findFirst().orElse(null);
        TestBlob resourceBlob = blobs.stream().filter(blob -> blob.type == ENTRY_TYPE_RESOURCE).findFirst().orElse(null);
        if (classBlob == null || resourceBlob == null) {
            throw new IOException("Payload self-test requires a class and a resource");
        }
        loadTestBlob(payload, classBlob, key, signature, indexTag, version);
        loadTestBlob(payload, resourceBlob, key, signature, indexTag, version);
        boolean wrongNonce = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            copy[(int) classBlob.offset] ^= 1;
            try {
                loadTestBlob(copy, classBlob, key, signature, indexTag, version);
            } finally {
                wipe(copy);
            }
        });
        boolean wrongTag = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            copy[(int) classBlob.offset + classBlob.blobLength - 1] ^= 1;
            try {
                loadTestBlob(copy, classBlob, key, signature, indexTag, version);
            } finally {
                wipe(copy);
            }
        });
        boolean wrongAad = expectPayloadFailure(() -> {
            byte[] nonce = copy(payload, (int) classBlob.offset, NONCE_LENGTH);
            byte[] cipher = copy(payload, (int) classBlob.offset + NONCE_LENGTH,
                    classBlob.blobLength - NONCE_LENGTH);
            byte[] aad = tagData(classBlob.path, classBlob.type, classBlob.clearLength,
                    classBlob.compressedLength, classBlob.paddingLength + 1, classBlob.hash,
                    signature, indexTag, version);
            try {
                decryptPayload(cipher, key, nonce, aad);
            } finally {
                wipe(nonce);
                wipe(cipher);
                wipe(aad);
            }
        });
        boolean wrongIndex = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            copy[HEADER_LENGTH] ^= 1;
            try {
                readTestIndex(copy, key, indexTag);
            } finally {
                wipe(copy);
            }
        });
        boolean wrongPadding = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            int paddingOffset = (int) classBlob.offset + NONCE_LENGTH + classBlob.compressedLength;
            copy[paddingOffset] ^= 1;
            try {
                loadTestBlob(copy, classBlob, key, signature, indexTag, version);
            } finally {
                wipe(copy);
            }
        });
        boolean corruptCompressed = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            byte[] nonce = copy(copy, (int) classBlob.offset, NONCE_LENGTH);
            byte[] cipher = copy(copy, (int) classBlob.offset + NONCE_LENGTH,
                    classBlob.blobLength - NONCE_LENGTH);
            byte[] aad = tagData(classBlob.path, classBlob.type, classBlob.clearLength,
                    classBlob.compressedLength, classBlob.paddingLength, classBlob.hash,
                    signature, indexTag, version);
            byte[] packed = null;
            byte[] changed = null;
            try {
                packed = decryptPayload(cipher, key, nonce, aad);
                packed[0] ^= 0x7f;
                changed = encrypt(packed, key, nonce, aad);
                System.arraycopy(changed, 0, copy, (int) classBlob.offset + NONCE_LENGTH, changed.length);
                loadTestBlob(copy, classBlob, key, signature, indexTag, version);
            } finally {
                wipe(nonce);
                wipe(cipher);
                wipe(aad);
                wipe(packed);
                wipe(changed);
                wipe(copy);
            }
        });
        boolean missingPayload = expectPayloadFailure(() -> requirePayload(null));
        boolean payloadMutation = expectPayloadFailure(() -> {
            byte[] copy = payload.clone();
            copy[(int) classBlob.offset + NONCE_LENGTH] ^= 1;
            try {
                loadTestBlob(copy, classBlob, key, signature, indexTag, version);
            } finally {
                wipe(copy);
            }
        });
        if (!wrongNonce || !wrongTag || !wrongAad || !wrongIndex || !wrongPadding
                || !corruptCompressed || !missingPayload || !payloadMutation) {
            throw new IOException("Payload self-test failed: nonce=" + wrongNonce + " tag=" + wrongTag
                    + " aad=" + wrongAad + " index=" + wrongIndex + " padding=" + wrongPadding
                    + " compression=" + corruptCompressed + " missing=" + missingPayload
                    + " mutation=" + payloadMutation);
        }
        report("Payload tests: class=PASS resource=PASS nonce=PASS tag=PASS aad=PASS"
                + " index=PASS padding=PASS compression=PASS missing=PASS mutation=PASS");
    }

    private static List<TestBlob> readTestIndex(byte[] payload, byte[] key, byte[] indexTag)
            throws Exception {
        requirePayload(payload);
        if (payload.length < HEADER_LENGTH + TAG_LENGTH) throw new IOException("Missing payload");
        int indexLength = readTestPackedInt(payload, 18);
        if (indexLength < TAG_LENGTH || HEADER_LENGTH + indexLength > payload.length) {
            throw new IOException("Invalid test index length");
        }
        byte[] nonce = copy(payload, 6, NONCE_LENGTH);
        byte[] cipher = copy(payload, HEADER_LENGTH, indexLength);
        byte[] index = null;
        try {
            index = decryptPayload(cipher, key, nonce, indexTag);
            List<TestBlob> result = new ArrayList<>();
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(index))) {
                int count = input.readInt();
                if (count <= 0 || count > 100_000) throw new IOException("Invalid test entry count");
                long dataStart = HEADER_LENGTH + indexLength;
                for (int i = 0; i < count; i++) {
                    String path = readTestString(input);
                    int type = input.readUnsignedByte();
                    long offset = input.readLong();
                    int blobLength = input.readInt();
                    int clearLength = input.readInt();
                    int compressedLength = input.readInt();
                    int paddingLength = input.readInt();
                    byte[] hash = input.readNBytes(HASH_LENGTH);
                    if ((type != ENTRY_TYPE_CLASS && type != ENTRY_TYPE_RESOURCE)
                            || offset < dataStart || blobLength != NONCE_LENGTH + compressedLength
                            + paddingLength + TAG_LENGTH || clearLength < 0 || compressedLength < 1
                            || paddingLength < 1 || offset > payload.length - blobLength
                            || hash.length != HASH_LENGTH) {
                        wipe(hash);
                        throw new IOException("Invalid test entry");
                    }
                    result.add(new TestBlob(path, type, offset, blobLength, clearLength,
                            compressedLength, paddingLength, hash));
                }
                int exclusions = input.readInt();
                if (exclusions < 0 || exclusions > 100_000) throw new IOException("Invalid exclusions");
                for (int i = 0; i < exclusions; i++) {
                    readTestString(input);
                    readTestString(input);
                }
                if (input.available() != 0) throw new IOException("Trailing test index bytes");
            }
            return result;
        } finally {
            wipe(nonce);
            wipe(cipher);
            wipe(index);
        }
    }

    private static void loadTestBlob(byte[] payload, TestBlob blob, byte[] key, byte[] signature,
            byte[] indexTag, int version) throws Exception {
        byte[] nonce = copy(payload, (int) blob.offset, NONCE_LENGTH);
        byte[] cipher = copy(payload, (int) blob.offset + NONCE_LENGTH,
                blob.blobLength - NONCE_LENGTH);
        byte[] aad = tagData(blob.path, blob.type, blob.clearLength, blob.compressedLength,
                blob.paddingLength, blob.hash, signature, indexTag, version);
        byte[] packed = null;
        byte[] compressed = null;
        byte[] clear = null;
        try {
            packed = decryptPayload(cipher, key, nonce, aad);
            if (packed.length != blob.compressedLength + blob.paddingLength) {
                throw new IOException("Invalid packed test length");
            }
            compressed = copy(packed, 0, blob.compressedLength);
            clear = inflate(compressed, blob.clearLength);
            if (!MessageDigest.isEqual(blob.hash, sha256(clear))) {
                throw new IOException("Test entry hash mismatch");
            }
        } finally {
            wipe(nonce);
            wipe(cipher);
            wipe(aad);
            wipe(packed);
            wipe(compressed);
            wipe(clear);
        }
    }

    private static byte[] decryptPayload(byte[] cipherText, byte[] key, byte[] nonce, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(cipherText);
    }

    private static byte[] inflate(byte[] compressed, int expectedLength) throws IOException {
        Inflater inflater = new Inflater();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.max(32, expectedLength));
        byte[] buffer = new byte[8192];
        try {
            inflater.setInput(compressed);
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    if (bytes.size() > expectedLength - count) throw new IOException("Inflated data too large");
                    bytes.write(buffer, 0, count);
                } else {
                    throw new IOException("Compressed data is invalid");
                }
            }
            if (bytes.size() != expectedLength || inflater.getRemaining() != 0) {
                throw new IOException("Compressed data length mismatch");
            }
            return bytes.toByteArray();
        } catch (DataFormatException failure) {
            throw new IOException("Compressed data is invalid", failure);
        } finally {
            inflater.end();
            wipe(buffer);
        }
    }

    private static void requirePayload(byte[] payload) throws IOException {
        if (payload == null || payload.length < HEADER_LENGTH + TAG_LENGTH) {
            throw new IOException("Missing payload");
        }
    }

    private static int readTestPackedInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static String readTestString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > 1_000_000) throw new IOException("Invalid test string length");
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new IOException("Truncated test string");
        try {
            return new String(bytes, StandardCharsets.UTF_8);
        } finally {
            wipe(bytes);
        }
    }

    private static boolean expectPayloadFailure(CheckedAction action) {
        try {
            action.run();
            return false;
        } catch (Exception expected) {
            return true;
        }
    }

    private static byte[] copy(byte[] source, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, offset, result, 0, length);
        return result;
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    private record TestBlob(String path, int type, long offset, int blobLength, int clearLength,
            int compressedLength, int paddingLength, byte[] hash) {
    }

    private static byte[] serializeIndex(List<Blob> blobs, Map<String, String> exclusions) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(blobs.size());
        for (Blob blob : blobs) {
            writeString(output, blob.path);
            output.writeByte(blob.type);
            output.writeLong(blob.offset);
            output.writeInt(blob.blob.length);
            output.writeInt(blob.clearLength);
            output.writeInt(blob.compressedLength);
            output.writeInt(blob.paddingLength);
            output.write(blob.hash);
        }
        output.writeInt(exclusions.size());
        for (Map.Entry<String, String> exclusion : exclusions.entrySet()) {
            writeString(output, exclusion.getKey());
            writeString(output, exclusion.getValue());
        }
        output.flush();
        return bytes.toByteArray();
    }

    private static byte[] encrypt(byte[] clear, byte[] key, byte[] nonce, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(clear);
    }

    private static byte[] tagData(String path, int type, int clearLength, int compressedLength,
            int paddingLength, byte[] hash, byte[] signature, byte[] indexTag, int version) throws IOException {
        byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(pathBytes.length + 80);
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(0x46504144);
        output.writeShort(version);
        output.writeInt(signature.length);
        output.write(signature);
        output.writeInt(indexTag.length);
        output.write(indexTag);
        output.writeByte(type);
        output.writeInt(pathBytes.length);
        output.write(pathBytes);
        output.writeInt(clearLength);
        output.writeInt(compressedLength);
        output.writeInt(paddingLength);
        output.write(hash);
        output.flush();
        return bytes.toByteArray();
    }

    private static int compressedLength(byte[] padded, int paddingLength) {
        return padded.length - paddingLength;
    }

    private static byte[] compress(byte[] clear, int compressionLevel) throws IOException {
        Deflater deflater = new Deflater(compressionLevel);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.max(64, clear.length / 2));
        byte[] buffer = new byte[8192];
        try {
            deflater.setInput(clear);
            deflater.finish();
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                if (count == 0 && !deflater.finished()) throw new IOException("Compression stalled");
                bytes.write(buffer, 0, count);
            }
            return bytes.toByteArray();
        } finally {
            deflater.end();
            wipe(buffer);
        }
    }

    private static byte[] sha256File(Path file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IOException("SHA-256 unavailable", failure);
        }
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) > 0) digest.update(buffer, 0, read);
        }
        return digest.digest();
    }

    private static byte[] buildWatermark(String customer) throws IOException {
        if (customer == null || customer.isBlank()) return randomBytes(24);
        byte[] seed = ("fabricpacker-watermark:" + customer).getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return java.util.Arrays.copyOf(digest.digest(seed), 24);
        } catch (NoSuchAlgorithmException failure) {
            throw new IOException("SHA-256 unavailable", failure);
        } finally {
            wipe(seed);
        }
    }

    private static byte[] generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey().getEncoded();
    }

    /**
     * Build-side reimplementation of the native {@code hkdf_mask}: HKDF-SHA256
     * (RFC 5869) with ikm = {@link #BAKED_IKM}, the per-build salt and info,
     * expanded to one 32-byte block. Must match native/pk_sha2.h byte for byte;
     * {@link #runNativeSelfTest} verifies this against the real DLL every build.
     */
    private static byte[] hkdfMask(byte[] salt, byte[] info) throws IOException {
        byte[] prk = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            prk = mac.doFinal(BAKED_IKM);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info);
            mac.update((byte) 0x01);
            return mac.doFinal();
        } catch (Exception failure) {
            throw new IOException("HKDF mask derivation failed", failure);
        } finally {
            wipe(prk);
        }
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] out = new byte[left.length];
        for (int i = 0; i < left.length; i++) out[i] = (byte) (left[i] ^ right[i]);
        return out;
    }

    /** Locates every available native crypto core (packcore.dll/.so/.dylib) to embed. */
    private static Map<String, Path> locateNativeCores() {
        List<Path> dirs = new ArrayList<>();
        String configured = System.getProperty("fabricpacker.native.source");
        if (configured != null && !configured.isBlank()) {
            Path c = Path.of(configured);
            dirs.add(c.getParent() != null ? c.getParent() : Path.of("."));
        }
        dirs.add(Path.of("native"));
        dirs.add(Path.of("."));
        try {
            var location = FabricPacker.class.getProtectionDomain().getCodeSource().getLocation();
            if (location != null && "file".equalsIgnoreCase(location.getProtocol())) {
                Path base = Path.of(location.toURI());
                Path directory = Files.isDirectory(base) ? base : base.getParent();
                if (directory != null) {
                    dirs.add(directory.resolve("native"));
                    dirs.add(directory);
                }
            }
        } catch (Exception ignored) {
            // Fall back to the working-directory candidates.
        }
        Map<String, Path> found = new LinkedHashMap<>();
        for (String ext : new String[]{".dll", ".so", ".dylib"}) {
            for (Path dir : dirs) {
                Path p = dir.resolve("packcore" + ext).toAbsolutePath().normalize();
                if (Files.isRegularFile(p)) {
                    found.put(ext, p);
                    break;
                }
            }
        }
        return found;
    }

    private static String currentOsExt() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) return ".dylib";
        if (os.contains("win")) return ".dll";
        return ".so";
    }

    /**
     * End-to-end validation of the native path against the real DLL: derives the
     * key natively from the shipped material/salt/info and decrypts the index and
     * one class blob, comparing them to the Java reference. This fails the build
     * if the Java HKDF and the native HKDF ever drift, or if the DLL is missing.
     */
    private static void runNativeSelfTest(byte[] payload, byte[] material, byte[] salt, byte[] info,
            byte[] signature, byte[] indexTag, int version, Path nativeCorePath, byte[] key)
            throws Exception {
        String previous = System.getProperty("fabricpacker.native.core");
        System.setProperty("fabricpacker.native.core", nativeCorePath.toAbsolutePath().toString());
        byte[] m = material.clone();
        byte[] s = salt.clone();
        byte[] inf = info.clone();
        long handle = 0;
        List<TestBlob> blobs = null;
        try {
            handle = N0.nk(m, s, inf);
            int indexLength = readTestPackedInt(payload, 18);
            byte[] indexNonce = copy(payload, 6, NONCE_LENGTH);
            byte[] nativeIndex = N0.nd(handle, indexNonce, indexTag, payload, HEADER_LENGTH, indexLength);
            byte[] javaIndex = decryptPayload(copy(payload, HEADER_LENGTH, indexLength), key,
                    indexNonce, indexTag);
            boolean indexOk = java.util.Arrays.equals(nativeIndex, javaIndex);
            wipe(indexNonce);
            wipe(nativeIndex);
            wipe(javaIndex);
            if (!indexOk) throw new IOException("Native index round-trip mismatch");

            blobs = readTestIndex(payload, key, indexTag);
            TestBlob blob = blobs.stream().filter(b -> b.type == ENTRY_TYPE_CLASS).findFirst()
                    .orElseThrow(() -> new IOException("Native self-test requires a class blob"));
            byte[] nonce = copy(payload, (int) blob.offset, NONCE_LENGTH);
            byte[] aad = tagData(blob.path, blob.type, blob.clearLength, blob.compressedLength,
                    blob.paddingLength, blob.hash, signature, indexTag, version);
            byte[] nativePacked = N0.nd(handle, nonce, aad, payload,
                    (int) blob.offset + NONCE_LENGTH, blob.blobLength - NONCE_LENGTH);
            byte[] javaPacked = decryptPayload(copy(payload, (int) blob.offset + NONCE_LENGTH,
                    blob.blobLength - NONCE_LENGTH), key, nonce, aad);
            boolean blobOk = java.util.Arrays.equals(nativePacked, javaPacked);
            wipe(nonce);
            wipe(aad);
            wipe(nativePacked);
            wipe(javaPacked);
            if (!blobOk) throw new IOException("Native blob round-trip mismatch");
            report("Native core tests: load=PASS index=PASS blob=PASS");
        } catch (RuntimeException nativeFailure) {
            throw new IOException("Native core self-test failed: " + nativeFailure.getMessage(),
                    nativeFailure);
        } finally {
            if (handle != 0) N0.nx(handle);
            wipe(m);
            wipe(s);
            wipe(inf);
            if (blobs != null) for (TestBlob b : blobs) wipe(b.hash);
            if (previous == null) System.clearProperty("fabricpacker.native.core");
            else System.setProperty("fabricpacker.native.core", previous);
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] result = new byte[length];
        new SecureRandom().nextBytes(result);
        return result;
    }

    private static String randomPayloadResource(SecureRandom random) {
        return PAYLOAD_RESOURCE_PREFIX
                + Integer.toUnsignedString(random.nextInt(), 36)
                + Integer.toUnsignedString(random.nextInt(), 36) + ".dat";
    }

    private static String randomSignatureResource(SecureRandom random) {
        return SIGNATURE_RESOURCE_PREFIX
                + Integer.toUnsignedString(random.nextInt(), 36)
                + Integer.toUnsignedString(random.nextInt(), 36) + ".sig";
    }

    private static String randomWatermarkResource(SecureRandom random) {
        return WATERMARK_RESOURCE_PREFIX
                + Integer.toUnsignedString(random.nextInt(), 36)
                + Integer.toUnsignedString(random.nextInt(), 36) + ".wm";
    }

    private static Map<String, byte[]> generateRuntimeParts(byte[] material, byte[] salt, byte[] info,
            Map<String, byte[]> integrity, byte[] signature, byte[] indexTag,
            String payloadResource, String signatureResource, byte[] publicKey, int version,
            Map<String, String> classNames,
            Set<String> loaderOwners, Map<String, String> methodNames,
            Map<String, String> fieldNames) throws IOException {
        int[] words = new int[KEY_WORDS];
        for (int i = 0; i < KEY_WORDS; i++) {
            int offset = i * 4;
            words[i] = ((material[offset] & 0xff) << 24) | ((material[offset + 1] & 0xff) << 16)
                    | ((material[offset + 2] & 0xff) << 8) | (material[offset + 3] & 0xff);
        }
        int[] permutation = new int[KEY_WORDS];
        int[] operation = new int[KEY_WORDS];
        int[] rotation = new int[KEY_WORDS];
        int[] mask = new int[KEY_WORDS];
        int[] addend = new int[KEY_WORDS];
        int[] first = new int[KEY_WORDS / 2];
        int[] second = new int[KEY_WORDS / 2];
        for (int i = 0; i < KEY_WORDS; i++) permutation[i] = i;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < KEY_WORDS; i++) {
            int swap = random.nextInt(KEY_WORDS - i) + i;
            int old = permutation[i];
            permutation[i] = permutation[swap];
            permutation[swap] = old;
            operation[i] = random.nextInt(4);
            rotation[i] = random.nextInt(31) + 1;
            mask[i] = random.nextInt();
            addend[i] = random.nextInt();
            int word = words[permutation[i]];
            int stored;
            switch (operation[i]) {
                case 0 -> stored = Integer.rotateLeft(word + addend[i], rotation[i]) ^ mask[i];
                case 1 -> stored = (Integer.rotateLeft(word, rotation[i]) ^ addend[i]) + mask[i];
                case 2 -> stored = (Integer.rotateLeft(word, rotation[i]) ^ mask[i]) - addend[i];
                default -> stored = (Integer.rotateLeft(word, rotation[i]) + addend[i]) ^ mask[i];
            }
            if (i < KEY_WORDS / 2) first[i] = stored;
            else second[i - KEY_WORDS / 2] = stored;
        }
        verifyGeneratedKey(material, permutation, operation, rotation, mask, addend, first, second);
        List<String> decoderStrings = new ArrayList<>(List.of(
                "AES/GCM/NoPadding",
                "SHA-256",
                payloadResource,
                "Packed payload is truncated",
                "Invalid packed payload signature",
                "Unsupported packed payload version: ",
                "Invalid packed index length",
                "Invalid packed entry count",
                "Invalid packed exclusion count",
                "Invalid or duplicate packed entry: ",
                "Trailing bytes in packed index",
                "Packed payload contains no entries",
                "Packed entry is outside the container: ",
                "Packed entry hash mismatch: ",
                "AES-GCM authentication failed for packed data",
                "Packed resource authentication failed: ",
                "Could not create packed resource URL",
                "Could not load packed class ",
                "Invalid packed string length",
                "Truncated packed index string",
                "Packed class loader is closed",
                "Missing loader class: ",
                "SHA-256 unavailable",
                "Loader integrity check failed: ",
                "Could not create packed class URL",
                "Fabric packer could not install its AES class loader",
                "getLauncher is not static",
                "Fabric launcher is not initialized",
                "Fabric target ClassLoader is missing",
                "Fabric target does not expose instance addUrlFwd(URL)",
                "AES",
                signatureResource,
                "Ed25519",
                "Signed asset manifest is invalid",
                "Signed asset hash mismatch: ",
                "Signed loader signature is invalid",
                "Runtime instrumentation is not supported"
        ));
        int nativeResourceId = decoderStrings.size();
        decoderStrings.add(NATIVE_RESOURCE);
        String pField = randomIdentifier(random);
        String oField = randomIdentifier(random);
        String rField = randomIdentifier(random);
        String mField = randomIdentifier(random);
        String qField = randomIdentifier(random);
        String firstField = randomIdentifier(random);
        String secondField = randomIdentifier(random);
        String a1 = "package fabricpacker;\nfinal class A1 {private static final int[] " + firstField + "="
                + ints(first) + ";private A1(){}static int a(int i){return " + firstField + "[i];}}\n";
        String a2 = "package fabricpacker;\nfinal class A2 {private static final int[] " + secondField + "="
                + ints(second) + ";private A2(){}static int a(int i){return " + secondField + "[i];}}\n";
        Map<String, String> keySources = new LinkedHashMap<>();
        keySources.put("fabricpacker.A1", a1);
        keySources.put("fabricpacker.A2", a2);
        Map<String, byte[]> keyParts = compileRuntimeParts(keySources);
        // Keep the generated key-part methods package-private. ProGuard can
        // tighten their access even with keep rules, which breaks cross-class
        // calls after the classes are loaded by Fabric.
        Map<String, byte[]> completeIntegrity = new LinkedHashMap<>(integrity);
        for (Map.Entry<String, byte[]> part : keyParts.entrySet()) {
            byte[] transformed = rewriteClass(part.getValue(), loaderOwners,
                    classNames, methodNames, fieldNames);
            try {
                completeIntegrity.put(remapClassPath(part.getKey(), classNames), sha256(transformed));
            } finally {
                wipe(transformed);
            }
        }
        StringBuilder integrityFields = new StringBuilder();
        StringBuilder integrityCalls = new StringBuilder();
        int integrityIndex = 0;
        for (Map.Entry<String, byte[]> check : completeIntegrity.entrySet()) {
            String field = randomIdentifier(random) + integrityIndex++;
            int pathStringId = decoderStrings.size();
            decoderStrings.add(check.getKey());
            integrityFields.append("private static final byte[] ").append(field)
                    .append('=').append(bytes(check.getValue())).append(';').append('\n');
            integrityCalls.append("e(l,A0.e(").append(pathStringId).append("),")
                    .append(field).append(");");
        }
        String decoderCases = runtimeDecoderCases(random, decoderStrings);
        String a0 = "package fabricpacker;\n"
                + "final class A0 {\n"
                + "private static final int[] " + pField + "=" + ints(permutation) + ";\n"
                + "private static final int[] " + oField + "=" + ints(operation) + ";\n"
                + "private static final int[] " + rField + "=" + ints(rotation) + ";\n"
                + "private static final int[] " + mField + "=" + ints(mask) + ";\n"
                + "private static final int[] " + qField + "=" + ints(addend) + ";\n"
                + integrityFields
                + "private A0(){}\n"
                + "static byte[] a(){byte[] out=new byte[32];for(int i=0;i<8;i++){int s=" + pField + "[i];int v=i<4?A1.a(i):A2.a(i-4);"
                + "switch(" + oField + "[i]){case 0:v=Integer.rotateRight(v^" + mField + "[i]," + rField + "[i])-" + qField + "[i];break;"
                + "case 1:v=Integer.rotateRight((v-" + mField + "[i])^" + qField + "[i]," + rField + "[i]);break;"
                + "case 2:v=Integer.rotateRight((v+" + qField + "[i])^" + mField + "[i]," + rField + "[i]);break;"
                + "default:v=Integer.rotateRight((v^" + mField + "[i])-" + qField + "[i]," + rField + "[i]);}int n=s*4;"
                + "out[n]=(byte)(v>>>24);out[n+1]=(byte)(v>>>16);out[n+2]=(byte)(v>>>8);out[n+3]=(byte)v;}return out;}\n"
                + "static void b(ClassLoader l)throws java.io.IOException{" + integrityCalls + "}\n"
                + "private static void e(ClassLoader l,String n,byte[] h)throws java.io.IOException{try(java.io.InputStream in=l.getResourceAsStream(n)){if(in==null)throw new java.io.IOException(A0.e(21)+n);byte[] d=in.readAllBytes();byte[] x;try{x=java.security.MessageDigest.getInstance(A0.e(1)).digest(d);}catch(Exception z){java.util.Arrays.fill(d,(byte)0);throw new java.io.IOException(A0.e(22),z);}java.util.Arrays.fill(d,(byte)0);if(!java.security.MessageDigest.isEqual(x,h)){java.util.Arrays.fill(x,(byte)0);throw new java.io.IOException(A0.e(23)+n);}java.util.Arrays.fill(x,(byte)0);}}\n"
                + "static byte[] c(){return new byte[]" + bytes(signature) + ";}\n"
                + "static byte[] d(){return new byte[]" + bytes(indexTag) + ";}\n"
                + "static int f(){return " + version + ";}\n"
                + "static byte[] g(){return new byte[]" + bytes(publicKey) + ";}\n"
                + "static byte[] h(){return new byte[]" + bytes(salt) + ";}\n"
                + "static byte[] i(){return new byte[]" + bytes(info) + ";}\n"
                + "static String n(){return e(" + nativeResourceId + ");}\n"
                + "static String e(int i){switch(i){" + decoderCases + "}throw new IllegalArgumentException();}\n"
                + "}\n";
        wipe(words);
        wipe(permutation);
        wipe(operation);
        wipe(rotation);
        wipe(mask);
        wipe(addend);
        wipe(first);
        wipe(second);
        Map<String, byte[]> a0Parts = compileRuntimeParts(
                java.util.Map.of("fabricpacker.A0", a0));
        Map<String, byte[]> result = new LinkedHashMap<>(a0Parts);
        result.putAll(keyParts);
        wipeHashMap(completeIntegrity);
        return result;
    }

    private static void verifyGeneratedKey(byte[] key, int[] permutation, int[] operation,
            int[] rotation, int[] mask, int[] addend, int[] first, int[] second) throws IOException {
        byte[] restored = new byte[key.length];
        for (int i = 0; i < KEY_WORDS; i++) {
            int value = i < KEY_WORDS / 2 ? first[i] : second[i - KEY_WORDS / 2];
            switch (operation[i]) {
                case 0 -> value = Integer.rotateRight(value ^ mask[i], rotation[i]) - addend[i];
                case 1 -> value = Integer.rotateRight((value - mask[i]) ^ addend[i], rotation[i]);
                case 2 -> value = Integer.rotateRight((value + addend[i]) ^ mask[i], rotation[i]);
                default -> value = Integer.rotateRight((value ^ mask[i]) - addend[i], rotation[i]);
            }
            int offset = permutation[i] * 4;
            restored[offset] = (byte) (value >>> 24);
            restored[offset + 1] = (byte) (value >>> 16);
            restored[offset + 2] = (byte) (value >>> 8);
            restored[offset + 3] = (byte) value;
        }
        boolean valid = MessageDigest.isEqual(key, restored);
        wipe(restored);
        if (!valid) throw new IOException("Generated runtime key parts failed self-check");
    }

    private static Map<String, byte[]> compileRuntimeParts(Map<String, String> sources) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IOException("A JDK is required to generate runtime parts");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        Map<String, byte[]> compiled = new LinkedHashMap<>();
        List<JavaFileObject> sourceFiles = new ArrayList<>();
        for (Map.Entry<String, String> source : sources.entrySet()) {
            sourceFiles.add(new SimpleJavaFileObject(
                    URI.create("string:///" + source.getKey().replace('.', '/') + ".java"), JavaFileObject.Kind.SOURCE) {
                @Override
                public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                    return source.getValue();
                }
            });
        }
        try (StandardJavaFileManager standard = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            JavaFileManager manager = new ForwardingJavaFileManager<>(standard) {
                @Override
                public JavaFileObject getJavaFileForOutput(JavaFileManager.Location location, String className,
                        JavaFileObject.Kind kind, FileObject sibling) {
                    return new SimpleJavaFileObject(URI.create("mem:///" + className.replace('.', '/') + kind.extension), kind) {
                        @Override
                        public java.io.OutputStream openOutputStream() {
                            return new ByteArrayOutputStream() {
                                @Override
                                public void close() throws IOException {
                                    compiled.put(className, toByteArray());
                                    super.close();
                                }
                            };
                        }
                    };
                }
            };
            Boolean success = compiler.getTask(null, manager, diagnostics, List.of("-g:none"), null,
                    sourceFiles).call();
            if (!Boolean.TRUE.equals(success) || compiled.size() != sources.size()) {
                throw new IOException("Could not generate runtime parts: " + diagnostics.getDiagnostics());
            }
            Map<String, byte[]> result = new LinkedHashMap<>();
            for (String className : sources.keySet()) {
                result.put(className.replace('.', '/') + ".class", compiled.get(className));
            }
            return result;
        }
    }

    private static String ints(int[] values) {
        StringBuilder result = new StringBuilder("{");
        for (int i = 0; i < values.length; i++) {
            if (i != 0) result.append(',');
            result.append(values[i]);
        }
        return result.append('}').toString();
    }

    private static String bytes(byte[] values) {
        StringBuilder result = new StringBuilder("{");
        for (int i = 0; i < values.length; i++) {
            if (i != 0) result.append(',');
            result.append(values[i]);
        }
        return result.append('}').toString();
    }

    private static String randomIdentifier(SecureRandom random) {
        return "q" + Integer.toUnsignedString(random.nextInt(), 36)
                + Integer.toUnsignedString(random.nextInt(), 36);
    }

    private static String runtimeDecoderCases(SecureRandom random, List<String> values) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i);
            int mask = random.nextInt(65535) + 1;
            result.append("case ").append(i).append(":{int k=").append(mask)
                    .append(";char[] q=new char[]{");
            for (int j = 0; j < value.length(); j++) {
                int encoded = (value.charAt(j) ^ mask) & 0xffff;
                if (j != 0) result.append(',');
                result.append("(char)").append(encoded);
            }
            result.append("};for(int j=0;j<q.length;j++)q[j]=(char)(q[j]^k);return new String(q);}");
        }
        return result.toString();
    }

    private static Map<String, String> runtimeClassNames() {
        SecureRandom random = new SecureRandom();
        Map<String, String> result = new LinkedHashMap<>();
        Set<String> used = new LinkedHashSet<>();
        String[] classes = {
                "fabricpacker/FabricBootstrap",
                "fabricpacker/PackedClassLoader",
                "fabricpacker/Guard",
                "fabricpacker/A0",
                "fabricpacker/A1",
                "fabricpacker/A2",
                "fabricpacker/PackedClassLoader$MemoryUrlHandler",
                "fabricpacker/PackedClassLoader$MemoryURLConnection",
                "fabricpacker/PackedClassLoader$WipingInputStream",
                "fabricpacker/PackedClassLoader$Entry"
        };
        for (String oldName : classes) {
            String newName;
            do {
                newName = "fabricpacker/P" + Integer.toUnsignedString(random.nextInt(), 36)
                        + Integer.toUnsignedString(random.nextInt(), 36);
            } while (!used.add(newName));
            result.put(oldName, newName);
        }
        return result;
    }

    private static final Set<String> RENAMABLE_METHODS = Set.of(
            "a", "b", "c", "d", "e", "f", "g", "rootUrl", "parseIndex", "parseIndexBytes",
            "readBlob", "openCipher", "tagData", "inflate", "readString", "validEntryPath",
            "normalizeResourceName", "openResource", "readRequired", "readPackedInt", "copy",
            "sha256", "wipe", "ensureOpen", "verifySignedAssets", "writeSignedString", "readSignedBytes",
            "guardRuntime", "findFabricTarget", "addToKnot", "check", "watch");

    private static final Set<String> RENAMABLE_FIELDS = Set.of(
            "VERSION", "NONCE_LENGTH", "TAG_LENGTH_BITS", "HASH_LENGTH", "HEADER_LENGTH",
            "PAYLOAD_RESOURCE", "SIGNATURE", "INDEX_TAG", "MAX_ENTRIES", "MAX_NAME_LENGTH",
            "resourceLoader", "entries", "container", "closed", "owner", "offset", "type",
            "blobLength", "clearLength", "compressedLength", "paddingLength", "hash");

    private record MemberDeclaration(String owner, String name, String descriptor,
                                     int nameIndexOffset, boolean method) {
    }

    private static final class ClassFileModel {
        final byte[] data;
        final int constantPoolCount;
        final int constantPoolEnd;
        final int[] tags;
        final int[] first;
        final int[] second;
        final int[] starts;
        final int[] ends;
        final String[] utf8;
        final String owner;
        final String superOwner;
        final List<MemberDeclaration> members;

        ClassFileModel(byte[] data, int constantPoolCount, int constantPoolEnd, int[] tags,
                int[] first, int[] second, int[] starts, int[] ends, String[] utf8,
                String owner, String superOwner, List<MemberDeclaration> members) {
            this.data = data;
            this.constantPoolCount = constantPoolCount;
            this.constantPoolEnd = constantPoolEnd;
            this.tags = tags;
            this.first = first;
            this.second = second;
            this.starts = starts;
            this.ends = ends;
            this.utf8 = utf8;
            this.owner = owner;
            this.superOwner = superOwner;
            this.members = members;
        }
    }

    private static final class ConstantPoolAppend {
        private int nextIndex;
        private final Map<String, Integer> utf8 = new LinkedHashMap<>();
        private final Map<String, Integer> nameAndTypes = new LinkedHashMap<>();
        private final List<byte[]> entries = new ArrayList<>();

        ConstantPoolAppend(int nextIndex) {
            this.nextIndex = nextIndex;
        }

        int utf8(String value) throws IOException {
            Integer existing = utf8.get(value);
            if (existing != null) return existing;
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 65535) throw new IOException("Loader UTF-8 entry is too long");
            ByteArrayOutputStream out = new ByteArrayOutputStream(bytes.length + 3);
            out.write(1);
            writeU2(out, bytes.length);
            out.write(bytes);
            int index = nextIndex++;
            utf8.put(value, index);
            entries.add(out.toByteArray());
            return index;
        }

        int nameAndType(String name, int descriptorIndex) throws IOException {
            String key = name + "\0" + descriptorIndex;
            Integer existing = nameAndTypes.get(key);
            if (existing != null) return existing;
            int nameIndex = utf8(name);
            ByteArrayOutputStream out = new ByteArrayOutputStream(5);
            out.write(12);
            writeU2(out, nameIndex);
            writeU2(out, descriptorIndex);
            int index = nextIndex++;
            nameAndTypes.put(key, index);
            entries.add(out.toByteArray());
            return index;
        }
    }

    private static String memberKey(String owner, String name, String descriptor) {
        return owner + "\0" + name + "\0" + descriptor;
    }

    private static String memberShortKey(String name, String descriptor) {
        return name + "\0" + descriptor;
    }

    private static Map<String, String> runtimeMethodNames(Map<String, byte[]> runtimeSources)
            throws IOException {
        SecureRandom random = new SecureRandom();
        Map<String, String> result = new LinkedHashMap<>();
        Set<String> used = new LinkedHashSet<>();
        for (Map.Entry<String, byte[]> source : runtimeSources.entrySet()) {
            for (MemberDeclaration member : parseClassFile(source.getValue()).members) {
                if (member.method() && RENAMABLE_METHODS.contains(member.name())
                        && !member.name().equals("<init>") && !member.name().equals("<clinit>")) {
                    result.put(memberKey(member.owner(), member.name(), member.descriptor()),
                            randomMemberName(random, used));
                }
            }
        }
        addGeneratedMethodNames(result, random, used);
        return result;
    }

    private static void addGeneratedMethodNames(Map<String, String> result, SecureRandom random,
            Set<String> used) {
        String[][] generated = {
                {"fabricpacker/A0", "a", "()[B"},
                {"fabricpacker/A0", "b", "(Ljava/lang/ClassLoader;)V"},
                {"fabricpacker/A0", "c", "()[B"},
                {"fabricpacker/A0", "d", "()[B"},
                {"fabricpacker/A0", "e", "(I)Ljava/lang/String;"},
                {"fabricpacker/A0", "e", "(Ljava/lang/ClassLoader;Ljava/lang/String;[B)V"},
                {"fabricpacker/A0", "f", "()I"},
                {"fabricpacker/A0", "g", "()[B"},
                {"fabricpacker/A0", "h", "()[B"},
                {"fabricpacker/A0", "i", "()[B"},
                {"fabricpacker/A0", "n", "()Ljava/lang/String;"},
                {"fabricpacker/A1", "a", "(I)I"},
                {"fabricpacker/A2", "a", "(I)I"}
        };
        for (String[] member : generated) {
            result.put(memberKey(member[0], member[1], member[2]), randomMemberName(random, used));
        }
    }

    private static String randomMemberName(SecureRandom random, Set<String> used) {
        String name;
        do {
            name = "m" + Integer.toUnsignedString(random.nextInt(), 36)
                    + Integer.toUnsignedString(random.nextInt(), 36);
        } while (!used.add(name));
        return name;
    }

    private static Map<String, String> runtimeFieldNames(Map<String, byte[]> runtimeSources)
            throws IOException {
        SecureRandom random = new SecureRandom();
        Map<String, String> result = new LinkedHashMap<>();
        Set<String> used = new LinkedHashSet<>();
        for (Map.Entry<String, byte[]> source : runtimeSources.entrySet()) {
            for (MemberDeclaration member : parseClassFile(source.getValue()).members) {
                if (!member.method() && RENAMABLE_FIELDS.contains(member.name())) {
                    result.put(memberKey(member.owner(), member.name(), member.descriptor()),
                            randomFieldName(random, used));
                }
            }
        }
        return result;
    }

    private static String randomFieldName(SecureRandom random, Set<String> used) {
        String name;
        do {
            name = "f" + Integer.toUnsignedString(random.nextInt(), 36)
                    + Integer.toUnsignedString(random.nextInt(), 36);
        } while (!used.add(name));
        return name;
    }

    private static String remapClassPath(String path, Map<String, String> classNames) {
        String internal = path.endsWith(".class")
                ? path.substring(0, path.length() - 6) : path;
        return classNames.getOrDefault(internal, internal) + (path.endsWith(".class") ? ".class" : "");
    }

    private static byte[] rewriteClass(byte[] classBytes, Set<String> loaderOwners,
            Map<String, String> classNames, Map<String, String> methodNames,
            Map<String, String> fieldNames) throws IOException {
        ClassFileModel model = parseClassFile(classBytes);
        Map<Integer, Integer> memberNameAndTypeReplacements = new LinkedHashMap<>();
        Map<Integer, Integer> declarationNameReplacements = new LinkedHashMap<>();
        ConstantPoolAppend appended = new ConstantPoolAppend(model.constantPoolCount);
        for (int index = 1; index < model.constantPoolCount; index++) {
            int tag = model.tags[index];
            if (tag != 9 && tag != 10 && tag != 11) continue;
            int nameAndType = model.second[index];
            if (nameAndType <= 0 || nameAndType >= model.constantPoolCount
                    || model.tags[nameAndType] != 12) continue;
            String owner = className(model.tags, model.first, model.utf8, model.first[index]);
            String name = utf8At(model.utf8, model.first[nameAndType]);
            String descriptor = utf8At(model.utf8, model.second[nameAndType]);
            if (!loaderOwners.contains(owner) || name.equals("<init>") || name.equals("<clinit>")) continue;
            Map<String, String> mappings = tag == 9 ? fieldNames : methodNames;
            String renamed = mappings.get(memberKey(owner, name, descriptor));
            if (renamed != null) {
                int replacement = appended.nameAndType(renamed, model.second[nameAndType]);
                memberNameAndTypeReplacements.put(index, replacement);
            }
        }
        for (MemberDeclaration member : model.members) {
            if (member.name().equals("<init>") || member.name().equals("<clinit>")) continue;
            Map<String, String> mappings = member.method() ? methodNames : fieldNames;
            String renamed = mappings.get(memberKey(member.owner(), member.name(), member.descriptor()));
            if (renamed != null) {
                declarationNameReplacements.put(member.nameIndexOffset(), appended.utf8(renamed));
            }
        }

        List<Map.Entry<String, String>> orderedClassMappings = new ArrayList<>(classNames.entrySet());
        orderedClassMappings.sort((left, right) -> Integer.compare(right.getKey().length(), left.getKey().length()));
        ByteArrayOutputStream rewritten = new ByteArrayOutputStream(classBytes.length + 128);
        rewritten.write(classBytes, 0, 8);
        int newConstantPoolCount = model.constantPoolCount + appended.entries.size();
        if (newConstantPoolCount > 65535) throw new IOException("Loader constant pool is too large");
        writeU2(rewritten, newConstantPoolCount);
        for (int index = 1; index < model.constantPoolCount; index++) {
            if (model.tags[index] == 0) continue;
            if (model.tags[index] == 1) {
                String updated = model.utf8[index];
                for (Map.Entry<String, String> mapping : orderedClassMappings) {
                    updated = updated.replace(mapping.getKey(), mapping.getValue());
                }
                for (Map.Entry<String, String> mapping : classNames.entrySet()) {
                    String oldSimple = mapping.getKey().substring(mapping.getKey().lastIndexOf('/') + 1);
                    if (updated.equals(oldSimple + ".java")) {
                        String newSimple = mapping.getValue().substring(mapping.getValue().lastIndexOf('/') + 1);
                        int nested = newSimple.indexOf('$');
                        if (nested >= 0) newSimple = newSimple.substring(0, nested);
                        updated = newSimple + ".java";
                        break;
                    }
                }
                writeUtf8(rewritten, updated);
            } else if (model.tags[index] == 9 || model.tags[index] == 10 || model.tags[index] == 11) {
                rewritten.write(model.tags[index]);
                writeU2(rewritten, model.first[index]);
                writeU2(rewritten, memberNameAndTypeReplacements.getOrDefault(index, model.second[index]));
            } else {
                copyBytes(classBytes, model.starts[index], model.ends[index] - model.starts[index], rewritten);
            }
        }
        for (byte[] entry : appended.entries) rewritten.write(entry);
        byte[] tail = java.util.Arrays.copyOfRange(classBytes, model.constantPoolEnd, classBytes.length);
        for (Map.Entry<Integer, Integer> replacement : declarationNameReplacements.entrySet()) {
            int relative = replacement.getKey() - model.constantPoolEnd;
            if (relative < 0 || relative + 2 > tail.length) throw new IOException("Invalid member declaration offset");
            writeU2(tail, relative, replacement.getValue());
        }
        rewritten.write(tail);
        java.util.Arrays.fill(tail, (byte) 0);
        return rewritten.toByteArray();
    }

    private static String className(int[] tags, int[] first, String[] utf8, int classIndex) {
        if (classIndex <= 0 || classIndex >= tags.length || tags[classIndex] != 7) return "";
        int nameIndex = first[classIndex];
        return nameIndex > 0 && nameIndex < utf8.length && utf8[nameIndex] != null ? utf8[nameIndex] : "";
    }

    private static int checkedOffset(byte[] data, int offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IOException("Truncated loader constant pool");
        }
        return offset + length;
    }

    private static ClassFileModel parseClassFile(byte[] data) throws IOException {
        if (data.length < 10 || readInt(data, 0) != 0xCAFEBABE) throw new IOException("Invalid loader classfile");
        int constantPoolCount = readU2(data, 8);
        int offset = 10;
        int[] tags = new int[constantPoolCount];
        int[] first = new int[constantPoolCount];
        int[] second = new int[constantPoolCount];
        int[] starts = new int[constantPoolCount];
        int[] ends = new int[constantPoolCount];
        String[] utf8 = new String[constantPoolCount];
        for (int index = 1; index < constantPoolCount; index++) {
            int start = offset;
            if (offset >= data.length) throw new IOException("Truncated loader constant pool");
            int tag = data[offset++] & 0xff;
            tags[index] = tag;
            switch (tag) {
                case 1 -> {
                    int length = readU2(data, offset);
                    offset = checkedOffset(data, offset, 2);
                    if (offset + length > data.length) throw new IOException("Truncated loader UTF-8 entry");
                    utf8[index] = new String(data, offset, length, StandardCharsets.UTF_8);
                    offset += length;
                }
                case 3, 4 -> offset = checkedOffset(data, offset, 4);
                case 5, 6 -> {
                    offset = checkedOffset(data, offset, 8);
                    starts[index] = start;
                    ends[index] = offset;
                    index++;
                    continue;
                }
                case 7, 8, 16, 19, 20 -> {
                    first[index] = readU2(data, offset);
                    offset = checkedOffset(data, offset, 2);
                }
                case 9, 10, 11, 12, 17, 18 -> {
                    first[index] = readU2(data, offset);
                    second[index] = readU2(data, offset + 2);
                    offset = checkedOffset(data, offset, 4);
                }
                case 15 -> offset = checkedOffset(data, offset, 3);
                default -> throw new IOException("Unsupported loader constant-pool tag: " + tag);
            }
            starts[index] = start;
            ends[index] = offset;
        }
        int constantPoolEnd = offset;
        int memberOffset = checkedOffset(data, constantPoolEnd, 8);
        int interfaces = readU2(data, constantPoolEnd + 6);
        memberOffset = checkedOffset(data, memberOffset, interfaces * 2);
        String owner = className(tags, first, utf8, readU2(data, constantPoolEnd + 2));
        String superOwner = className(tags, first, utf8, readU2(data, constantPoolEnd + 4));
        List<MemberDeclaration> members = new ArrayList<>();
        int fields = readU2(data, memberOffset);
        memberOffset = checkedOffset(data, memberOffset, 2);
        for (int i = 0; i < fields; i++) {
            int start = memberOffset;
            memberOffset = checkedOffset(data, memberOffset, 8);
            int nameIndex = readU2(data, start + 2);
            int descriptorIndex = readU2(data, start + 4);
            members.add(new MemberDeclaration(owner, utf8At(utf8, nameIndex),
                    utf8At(utf8, descriptorIndex), start + 2, false));
            memberOffset = checkedAttributes(data, memberOffset, readU2(data, start + 6));
        }
        int methods = readU2(data, memberOffset);
        memberOffset = checkedOffset(data, memberOffset, 2);
        for (int i = 0; i < methods; i++) {
            int start = memberOffset;
            memberOffset = checkedOffset(data, memberOffset, 8);
            int nameIndex = readU2(data, start + 2);
            int descriptorIndex = readU2(data, start + 4);
            members.add(new MemberDeclaration(owner, utf8At(utf8, nameIndex),
                    utf8At(utf8, descriptorIndex), start + 2, true));
            memberOffset = checkedAttributes(data, memberOffset, readU2(data, start + 6));
        }
        return new ClassFileModel(data, constantPoolCount, constantPoolEnd, tags, first, second,
                starts, ends, utf8, owner, superOwner, members);
    }

    private static String utf8At(String[] values, int index) {
        return index > 0 && index < values.length && values[index] != null ? values[index] : "";
    }

    private static void writeUtf8(ByteArrayOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 65535) throw new IOException("Loader UTF-8 entry is too long");
        output.write(1);
        writeU2(output, bytes.length);
        output.write(bytes);
    }

    private static int checkedAttributes(byte[] data, int offset, int count) throws IOException {
        for (int i = 0; i < count; i++) {
            offset = checkedOffset(data, offset, 6);
            int length = readInt(data, offset - 4);
            if (length < 0) throw new IOException("Invalid loader attribute length");
            offset = checkedOffset(data, offset, length);
        }
        return offset;
    }

    private static int readU2(byte[] data, int offset) throws IOException {
        if (offset < 0 || offset + 2 > data.length) throw new IOException("Truncated classfile");
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static int readInt(byte[] data, int offset) throws IOException {
        if (offset < 0 || offset + 4 > data.length) throw new IOException("Truncated classfile");
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static void writeU2(ByteArrayOutputStream output, int value) {
        output.write((value >>> 8) & 0xff);
        output.write(value & 0xff);
    }

    private static void writeU2(byte[] output, int offset, int value) {
        output[offset] = (byte) (value >>> 8);
        output[offset + 1] = (byte) value;
    }

    private static List<String> memberReferences(ClassFileModel model, Set<String> ownersToSkip)
            throws IOException {
        List<String> references = new ArrayList<>();
        for (int index = 1; index < model.constantPoolCount; index++) {
            int tag = model.tags[index];
            if (tag != 9 && tag != 10 && tag != 11) continue;
            int nat = model.second[index];
            if (nat <= 0 || nat >= model.constantPoolCount || model.tags[nat] != 12) continue;
            String owner = className(model.tags, model.first, model.utf8, model.first[index]);
            if (ownersToSkip.contains(owner)) continue;
            String name = utf8At(model.utf8, model.first[nat]);
            String descriptor = utf8At(model.utf8, model.second[nat]);
            references.add(tag + ":" + owner + ":" + name + ":" + descriptor);
        }
        return references;
    }

    private static void runLoaderRewriteSelfTests(Map<String, byte[]> runtimeSources,
            Set<String> loaderOwners, Map<String, String> classNames,
            Map<String, String> methodNames, Map<String, String> fieldNames) throws IOException {
        Set<String> internalOwners = new LinkedHashSet<>(loaderOwners);
        internalOwners.addAll(classNames.values());
        Set<String> expectedInflater = Set.of(
                "10:java/util/zip/Inflater:inflate:([B)I",
                "10:java/util/zip/Inflater:setInput:([B)V",
                "10:java/util/zip/Inflater:finished:()Z",
                "10:java/util/zip/Inflater:getRemaining:()I",
                "10:java/util/zip/Inflater:end:()V");
        Set<String> foundInflater = new LinkedHashSet<>();
        Map<String, byte[]> rewritten = new LinkedHashMap<>();
        try {
            for (Map.Entry<String, byte[]> source : runtimeSources.entrySet()) {
                ClassFileModel original = parseClassFile(source.getValue());
                byte[] copy = rewriteClass(source.getValue(), loaderOwners, classNames, methodNames, fieldNames);
                rewritten.put(remapClassPath(source.getKey() + ".class", classNames), copy);
                ClassFileModel changed = parseClassFile(copy);
                List<String> beforeExternal = memberReferences(original, internalOwners);
                List<String> afterExternal = memberReferences(changed, internalOwners);
                if (!beforeExternal.equals(afterExternal)) {
                    throw new IOException("Owner-safe rewrite changed an external member reference in " + source.getKey());
                }
                for (String reference : afterExternal) {
                    if (reference.startsWith("10:java/util/zip/Inflater:")
                            || reference.startsWith("11:java/util/zip/Inflater:")) {
                        foundInflater.add(reference);
                    }
                }
            }
            if (!foundInflater.containsAll(expectedInflater)) {
                throw new IOException("Owner-safe rewrite regression: Inflater members were changed or lost: "
                        + expectedInflater + " found=" + foundInflater);
            }
            validateLoaderReferences(rewritten);
        } finally {
            wipeMap(rewritten);
        }
    }

    private static void validateLoaderReferences(Map<String, byte[]> runtimeClasses) throws IOException {
        Map<String, ClassFileModel> byOwner = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : runtimeClasses.entrySet()) {
            if (!entry.getKey().endsWith(".class")) continue;
            ClassFileModel model = parseClassFile(entry.getValue());
            byOwner.put(model.owner, model);
        }
        for (ClassFileModel model : byOwner.values()) {
            Set<String> methods = new LinkedHashSet<>();
            Set<String> fields = new LinkedHashSet<>();
            for (MemberDeclaration declaration : model.members) {
                if (declaration.method()) methods.add(memberShortKey(declaration.name(), declaration.descriptor()));
                else fields.add(memberShortKey(declaration.name(), declaration.descriptor()));
            }
            for (int index = 1; index < model.constantPoolCount; index++) {
                int tag = model.tags[index];
                if (tag != 9 && tag != 10 && tag != 11) continue;
                int nat = model.second[index];
                if (nat <= 0 || nat >= model.constantPoolCount || model.tags[nat] != 12) continue;
                String owner = className(model.tags, model.first, model.utf8, model.first[index]);
                ClassFileModel target = byOwner.get(owner);
                if (target == null) continue;
                String name = utf8At(model.utf8, model.first[nat]);
                String descriptor = utf8At(model.utf8, model.second[nat]);
                if (name.equals("<init>") || name.equals("<clinit>")) continue;
                boolean declared = tag == 9
                        ? resolvesField(byOwner, target, name, descriptor, new LinkedHashSet<>())
                        : resolvesMethod(byOwner, target, name, descriptor, new LinkedHashSet<>());
                if (!declared) {
                    throw new IOException("Loader reference validation failed: " + model.owner
                            + " -> " + owner + "." + name + descriptor);
                }
            }
        }
    }

    private static Set<String> methodsFor(ClassFileModel model) {
        Set<String> result = new LinkedHashSet<>();
        for (MemberDeclaration member : model.members) {
            if (member.method()) result.add(memberShortKey(member.name(), member.descriptor()));
        }
        return result;
    }

    private static boolean resolvesMethod(Map<String, ClassFileModel> byOwner, ClassFileModel owner,
            String name, String descriptor, Set<String> visited) {
        if (!visited.add(owner.owner)) return false;
        if (methodsFor(owner).contains(memberShortKey(name, descriptor))) return true;
        if (owner.superOwner.isEmpty()) return false;
        ClassFileModel parent = byOwner.get(owner.superOwner);
        return parent == null || resolvesMethod(byOwner, parent, name, descriptor, visited);
    }

    private static boolean resolvesField(Map<String, ClassFileModel> byOwner, ClassFileModel owner,
            String name, String descriptor, Set<String> visited) {
        if (!visited.add(owner.owner)) return false;
        if (fieldsFor(owner).contains(memberShortKey(name, descriptor))) return true;
        if (owner.superOwner.isEmpty()) return false;
        ClassFileModel parent = byOwner.get(owner.superOwner);
        return parent == null || resolvesField(byOwner, parent, name, descriptor, visited);
    }

    private static Set<String> fieldsFor(ClassFileModel model) {
        Set<String> result = new LinkedHashSet<>();
        for (MemberDeclaration member : model.members) {
            if (!member.method()) result.add(memberShortKey(member.name(), member.descriptor()));
        }
        return result;
    }

    private static void copyBytes(byte[] source, int offset, int length, ByteArrayOutputStream target)
            throws IOException {
        if (offset < 0 || offset + length > source.length) throw new IOException("Truncated classfile");
        target.write(source, offset, length);
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static Map<String, byte[]> readEntries(Path input) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(input.toFile())) {
            Enumeration<JarEntry> enumeration = jar.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (entry.isDirectory()) continue;
                if (entries.put(entry.getName(), read(jar, entry)) != null) {
                    throw new IOException("Duplicate JAR entry: " + entry.getName());
                }
            }
        }
        return entries;
    }

    private static void writeJar(Path output, Map<String, byte[]> entries) throws IOException {
        Files.deleteIfExists(output);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output), manifest)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                JarEntry target = new JarEntry(entry.getKey());
                target.setTime(0L);
                jar.putNextEntry(target);
                jar.write(entry.getValue());
                jar.closeEntry();
            }
        }
    }

    private static List<String> leakTerms(List<String> extraTerms) {
        List<String> terms = new ArrayList<>(List.of(LEAK_TERMS));
        for (String term : extraTerms) {
            if (!term.isBlank()) terms.add(term);
        }
        return terms;
    }

    private static void verifyOutputJar(Path output, String payloadResource, String signatureResource,
            Map<String, byte[]> protectedEntries, byte[] key, byte[] publicKey, byte[] privateEncoded,
            List<String> extraLeakTerms, String nativeResource) throws IOException {
        Map<String, byte[]> entries = readEntries(output);
        try {
            if (entries.containsKey("fabricpacker.key") || entries.containsKey("fabricpacker/jar.dat")) {
                throw new IOException("Output contains a forbidden legacy key or payload entry");
            }
            if (entries.containsKey("fabric-packer.jar")) {
                throw new IOException("The packer itself was copied into the output JAR");
            }
            byte[] payload = entries.get(payloadResource);
            if (payload == null) throw new IOException("Generated payload entry is missing");
            if (!SignatureSupport.verify(entries, signatureResource, publicKey, payloadResource)) {
                throw new IOException("Ed25519 signature verification failed for generated output");
            }
            Set<String> protectedPaths = protectedEntries.keySet();
            for (String path : protectedPaths) {
                if (path.endsWith(".class") && entries.containsKey(path)) {
                    throw new IOException("Protected class is visible outside the payload: " + path);
                }
            }
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String path = entry.getKey();
                if (path.equals(signatureResource) || path.equals(payloadResource)
                        || path.startsWith(nativeResource)
                        || (path.startsWith("fabricpacker/") && path.endsWith(".class"))) continue;
                if (path.endsWith(".java")) {
                    throw new IOException("Leak check critical: path=" + path
                            + " type=source-file reason=clear Java source outside payload");
                }
                if (isAllowedVisible(path)) continue;
                String text = new String(entry.getValue(), StandardCharsets.ISO_8859_1);
                for (String term : leakTerms(extraLeakTerms)) {
                    if (text.contains(term) || path.contains(term)) {
                        throw new IOException("Leak check critical: path=" + path
                                + " type=clear-feature-string reason=protected term visible: " + term);
                    }
                }
                for (String pathName : protectedPaths) {
                    if (!pathName.endsWith(".class")) continue;
                    String dotted = pathName.substring(0, pathName.length() - 6).replace('/', '.');
                    String simple = dotted.substring(dotted.lastIndexOf('.') + 1);
                    if (simple.length() >= 5 && text.contains(simple)) {
                        throw new IOException("Leak check critical: path=" + path
                                + " type=protected-class-name reason=clear implementation name visible: " + simple);
                    }
                }
            }
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String path = entry.getKey();
                if (path.endsWith(".jar") && path.toLowerCase(java.util.Locale.ROOT).contains("fabric-packer")) {
                    throw new IOException("Build tool JAR leaked into output: " + path);
                }
                if (!path.startsWith("fabricpacker/") || !path.endsWith(".class")) continue;
                String text = new String(entry.getValue(), StandardCharsets.ISO_8859_1);
                for (String forbidden : new String[]{
                        "fabricpacker.key", "AES/GCM/NoPadding", "SHA-256", "decrypt",
                        "openCipher", "reconstruct", "parseIndex", "readBlob", "readRequired",
                        "tagData", "sha256", "KeyMaterial"}) {
                    if (text.contains(forbidden)) {
                        throw new IOException("Forbidden loader text remains: " + forbidden);
                    }
                }
                if (containsSequence(entry.getValue(), key)) {
                    throw new IOException("Complete payload key is visible in loader bytecode");
                }
            }
            for (byte[] value : entries.values()) {
                if (containsSequence(value, privateEncoded)) {
                    throw new IOException("Private Ed25519 signing key is visible in output JAR");
                }
            }
            // Ciphertext is intentionally random-looking. Searching it for short
            // words or package fragments would produce false positives by chance.
            // Protected names are checked in every visible entry above; the
            // encrypted index and entries are authenticated by the payload tests
            // and by the signed output verification.
        } finally {
            wipeMap(entries);
        }
    }

    private static boolean containsSequence(byte[] data, byte[] needle) {
        if (needle == null || needle.length == 0 || needle.length > data.length) return false;
        outer: for (int i = 0; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static void verifyOutputDirectory(Path directory, Path input, Path output) throws IOException {
        if (directory == null || !Files.isDirectory(directory)) return;
        Path inputPath = input.toAbsolutePath().normalize();
        Path outputPath = output.toAbsolutePath().normalize();
        Path packerPath = directory.resolve("fabric-packer.jar").toAbsolutePath().normalize();
        Path toolsPath = directory.resolve("tools").toAbsolutePath().normalize();
        try (var paths = Files.list(directory)) {
            for (Path path : (Iterable<Path>) paths::iterator) {
                if (!Files.isRegularFile(path)) continue;
                Path absolute = path.toAbsolutePath().normalize();
                if (absolute.equals(inputPath) || absolute.equals(outputPath)
                        || absolute.equals(packerPath) || absolute.startsWith(toolsPath)) continue;
                String name = path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                if (name.equals("fabricpacker.key") || name.endsWith(".class") || name.endsWith(".bin")
                        || name.endsWith(".java") || name.endsWith(".pk8") || name.endsWith(".pem")
                        || name.endsWith(".key") || name.contains("decrypted")
                        || name.contains("plaintext") || name.contains("cleartext")) {
                    throw new IOException("Leak check critical: path=" + path
                            + " type=output-file reason=unprotected build output");
                }
            }
        }
    }

    private static boolean isAllowedVisible(String path) {
        return path.equals(FABRIC_MOD) || path.endsWith(".mixins.json") || path.endsWith(".refmap.json")
                || path.startsWith("META-INF/") || path.contains("/mixin/")
                || path.endsWith("AddonTemplate.class") || path.endsWith("modules/NameProtect.class")
                || path.equals("com/example/addon/protection/network/ProtectionComponentCodec.class")
                || path.equals("com/example/addon/protection/detection/PacketContext.class")
                || path.equals("com/example/addon/protection/network/ProtectionFromPacketAccess.class");
    }

    private static boolean shouldRemainPlain(String path, Set<String> excluded) {
        if (path.equals(FABRIC_MOD) || isExcludedResource(path, excluded)) return true;
        if (path.endsWith(".mixins.json") || path.endsWith(".refmap.json")) return true;
        if (path.startsWith("META-INF/jars/") || path.startsWith("META-INF/services/")) return true;
        return false;
    }

    private static boolean isExcludedClass(String classPath, Set<String> excluded) {
        String className = classPath.substring(0, classPath.length() - 6);
        for (String raw : excluded) {
            String value = raw.replace('.', '/').replaceAll("/+$", "");
            if (className.equals(value) || className.startsWith(value + "/")) return true;
        }
        return false;
    }

    private static boolean isExcludedResource(String path, Set<String> excluded) {
        if (excluded.contains(path)) return true;
        return excluded.contains(path.replace('/', '.'));
    }

    private static boolean isSignature(String path) {
        String upper = path.toUpperCase(java.util.Locale.ROOT);
        return upper.startsWith("META-INF/") && (upper.endsWith(".SF") || upper.endsWith(".RSA")
                || upper.endsWith(".DSA") || upper.endsWith(".EC"));
    }

    private static boolean isRuntimeClass(String path) {
        for (String runtime : RUNTIME_CLASSES) {
            if (runtime.equals(path)) return true;
        }
        return false;
    }

    private static byte[] rewriteVisibleMetadata(String path, byte[] value,
            Map<String, String> classNames) {
        if (!path.startsWith("META-INF/services/")) return value;
        String text = new String(value, StandardCharsets.UTF_8);
        for (Map.Entry<String, String> mapping : classNames.entrySet()) {
            text = text.replace(mapping.getKey().replace('/', '.'),
                    mapping.getValue().replace('/', '.'));
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static void rejectReservedInput(String path) throws IOException {
        if ((path.startsWith(PAYLOAD_RESOURCE_PREFIX) && path.endsWith(".dat"))
                || path.equals("fabricpacker/jar.dat") || path.equals("fabricpacker.key")
                || path.equals("fabricpacker/manifest.properties") || path.startsWith("encrypted/")) {
            throw new IOException("Input already contains an old Fabric Packer payload: " + path);
        }
    }

    private static void collectEntrypointExcludes(Map<String, Object> metadata, Set<String> excludes)
            throws IOException {
        Object raw = metadata.get("entrypoints");
        if (!(raw instanceof Map<?, ?>)) return;
        for (Object value : ((Map<?, ?>) raw).values()) collectClassStrings(value, excludes);
    }

    private static void collectMixinExcludes(Map<String, Object> metadata, Map<String, byte[]> entries,
            Set<String> excludes) throws IOException {
        Object raw = metadata.get("mixins");
        if (raw instanceof String) collectMixinConfig((String) raw, entries, excludes);
        else if (raw instanceof List<?>) {
            for (Object item : (List<?>) raw) {
                if (item instanceof String) collectMixinConfig((String) item, entries, excludes);
                else if (item instanceof Map<?, ?>) {
                    Object config = ((Map<?, ?>) item).get("config");
                    if (config instanceof String) collectMixinConfig((String) config, entries, excludes);
                }
            }
        }
        for (String path : entries.keySet()) {
            if (path.endsWith(".refmap.json") || path.endsWith(".mixins.json")) excludes.add(path);
        }
    }

    private static void collectMixinConfig(String path, Map<String, byte[]> entries, Set<String> excludes)
            throws IOException {
        excludes.add(path);
        byte[] bytes = entries.get(path);
        if (bytes == null) throw new IOException("Missing mixin config: " + path);
        Map<String, Object> config = SimpleJson.object(
                SimpleJson.parse(new String(bytes, StandardCharsets.UTF_8), path), path + " must be an object");
        Object packageValue = config.get("package");
        String packageName = packageValue instanceof String ? (String) packageValue : "";
        if (!packageName.isEmpty()) excludes.add(packageName);
        Object refmap = config.get("refmap");
        if (refmap instanceof String) excludes.add((String) refmap);
        for (String key : new String[]{"mixins", "client", "server"}) {
            Object values = config.get(key);
            if (values instanceof List<?>) {
                for (Object value : (List<?>) values) {
                    if (value instanceof String) {
                        String className = (String) value;
                        excludes.add(packageName.isEmpty() || className.contains(".")
                                ? className : packageName + "." + className);
                    }
                }
            }
        }
    }

    private static void collectClassStrings(Object value, Set<String> excludes) throws IOException {
        if (value instanceof String) excludes.add((String) value);
        else if (value instanceof List<?>) for (Object item : (List<?>) value) collectClassStrings(item, excludes);
        else if (value instanceof Map<?, ?>) {
            Object entrypoint = ((Map<?, ?>) value).get("value");
            if (entrypoint != null) collectClassStrings(entrypoint, excludes);
        } else if (value != null) throw new IOException("Entrypoint value must be a string or array");
    }

    record PackConfig(Set<String> excludes, List<String> leakTerms, int compression, int parallelism) {
    }

    private static PackConfig readConfig(String json) throws IOException {
        Object parsed = SimpleJson.parse(json, "config.json");
        Set<String> excludes = new LinkedHashSet<>();
        collectConfiguredValues(parsed, excludes, null);
        List<String> leakTerms = new ArrayList<>();
        int compression = Deflater.BEST_COMPRESSION;
        int parallelism = Math.max(1, Runtime.getRuntime().availableProcessors());
        if (parsed instanceof Map<?, ?> map) {
            Object leakValue = map.get("leakTerms");
            if (leakValue instanceof List<?> values) {
                for (Object value : values) {
                    if (value instanceof String term && !term.isBlank()) leakTerms.add(term);
                    else throw new IOException("config.json leakTerms must be a list of non-empty strings");
                }
            } else if (leakValue != null) {
                throw new IOException("config.json leakTerms must be a list of strings");
            }
            compression = readConfigInt(map, "compression", compression, 1, 9);
            parallelism = readConfigInt(map, "parallelism", parallelism, 1, 32);
            warnUnknownConfigKeys(map);
        }
        return new PackConfig(excludes, List.copyOf(leakTerms), compression, parallelism);
    }

    private static int readConfigInt(Map<?, ?> map, String key, int fallback, int min, int max) throws IOException {
        Object value = map.get(key);
        if (value == null) return fallback;
        if (!(value instanceof BigDecimal number)) throw new IOException("config.json " + key + " must be a number");
        int result;
        try {
            result = number.intValueExact();
        } catch (ArithmeticException failure) {
            throw new IOException("config.json " + key + " must be an integer", failure);
        }
        if (result < min || result > max) {
            throw new IOException("config.json " + key + " must be between " + min + " and " + max);
        }
        return result;
    }

    private static void warnUnknownConfigKeys(Map<?, ?> map) {
        for (Object key : map.keySet()) {
            if (!(key instanceof String name)) continue;
            switch (name) {
                case "class", "classes", "exempt", "packages", "resources", "leakTerms",
                        "compression", "parallelism", "visible" -> {
                    // Understood: read as visibility rules / packer options.
                }
                case "obfuscation" -> report("Note: config.json 'obfuscation' is ignored - "
                        + "the packer encrypts mod classes but does not rename/obfuscate them.");
                case "libraries" -> report("Note: config.json 'libraries' is ignored - "
                        + "the packer repacks compiled classes and resolves no dependencies.");
                default -> report("Warning: unknown config.json key: " + name);
            }
        }
    }

    private static void collectConfiguredValues(Object value, Set<String> result, String mode) {
        if (value instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                String key = entry.getKey() instanceof String ? (String) entry.getKey() : "";
                String next = mode;
                if (key.equals("class") || key.equals("packages") || key.equals("classes")
                        || key.equals("exclude") || key.equals("exempt")) next = "class";
                else if (key.equals("resources")) next = "resource";
                collectConfiguredValues(entry.getValue(), result, next);
            }
        } else if (value instanceof List<?> && mode != null) {
            for (Object item : (List<?>) value) collectConfiguredValues(item, result, mode);
        } else if (value instanceof String && mode != null) {
            result.add(mode.equals("resource") ? (String) value : normalizeExclude((String) value));
        }
    }

    private static String normalizeExclude(String value) {
        return value.replace('.', '/').replaceAll("/+$", "");
    }

    private static Map<String, Object> withPreLaunch(Map<String, Object> original,
            Map<String, String> classNames) throws IOException {
        Map<String, Object> result = new LinkedHashMap<>(original);
        Map<String, Object> entrypoints = new LinkedHashMap<>();
        Object raw = result.get("entrypoints");
        if (raw instanceof Map<?, ?>) {
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) raw).entrySet()) {
                if (!(entry.getKey() instanceof String)) throw new IOException("Non-string entrypoint key");
                entrypoints.put((String) entry.getKey(), entry.getValue());
            }
        }
        List<Object> preLaunch = new ArrayList<>();
        Object existing = entrypoints.get("preLaunch");
        if (existing instanceof String) preLaunch.add(existing);
        else if (existing instanceof List<?>) preLaunch.addAll((List<?>) existing);
        else if (existing != null) throw new IOException("entrypoints.preLaunch must be a string or array");
        String bootstrap = classNames.getOrDefault("fabricpacker/FabricBootstrap",
                "fabricpacker/FabricBootstrap").replace('/', '.');
        for (int i = 0; i < preLaunch.size(); i++) {
            if ("fabricpacker.FabricBootstrap".equals(preLaunch.get(i))) preLaunch.set(i, bootstrap);
        }
        if (!preLaunch.contains(bootstrap)) preLaunch.add(bootstrap);
        entrypoints.put("preLaunch", preLaunch);
        result.put("entrypoints", entrypoints);
        remapMetadataClassNames(result, classNames);
        return result;
    }

    private static void remapMetadataClassNames(Object value, Map<String, String> classNames) {
        if (value instanceof Map<?, ?> map) {
            for (Object raw : map.entrySet()) {
                Map.Entry<?, ?> entry = (Map.Entry<?, ?>) raw;
                if (entry.getValue() instanceof String string && entry.getKey() != null) {
                    String updated = string;
                    for (Map.Entry<String, String> mapping : classNames.entrySet()) {
                        updated = updated.replace(mapping.getKey().replace('/', '.'),
                                mapping.getValue().replace('/', '.'));
                    }
                    ((Map<Object, Object>) map).put(entry.getKey(), updated);
                } else {
                    remapMetadataClassNames(entry.getValue(), classNames);
                }
            }
        } else if (value instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                if (item instanceof String string) {
                    String updated = string;
                    for (Map.Entry<String, String> mapping : classNames.entrySet()) {
                        updated = updated.replace(mapping.getKey().replace('/', '.'),
                                mapping.getValue().replace('/', '.'));
                    }
                    ((List<Object>) list).set(i, updated);
                } else {
                    remapMetadataClassNames(item, classNames);
                }
            }
        }
    }

    private static String exclusionReason(String classPath, Set<String> exclusions) {
        String className = classPath.substring(0, classPath.length() - 6).replace('/', '.');
        for (String raw : exclusions) {
            String value = raw.replace('/', '.').replaceAll("\\.+$", "");
            if (className.equals(value) || className.startsWith(value + ".")) return value;
        }
        return "required Fabric-visible class";
    }

    private static String exclusionReasonFor(String value) {
        if (value.equals("fabricpacker.FabricBootstrap")) return "bootstrap";
        if (value.equals("fabricpacker.PackedClassLoader")) return "runtime loader";
        if (value.endsWith(".refmap.json")) return "mixin refmap";
        if (value.endsWith(".mixins.json")) return "mixin config";
        if (value.contains("mixin")) return "mixin class or package";
        if (value.startsWith("META-INF/jars/") || value.startsWith("META-INF/services/")) return "Fabric metadata";
        return "entrypoint or configured exclusion";
    }

    private static byte[] readOwnResource(String path) throws IOException {
        try (InputStream stream = FabricPacker.class.getClassLoader().getResourceAsStream(path)) {
            if (stream == null) throw new IOException("Packer runtime resource is missing: " + path);
            return stream.readAllBytes();
        }
    }

    private static SigningMaterial loadSigningMaterial(Path output) throws IOException {
        String privatePathValue = System.getProperty("fabricpacker.signing.privateKey");
        if (privatePathValue == null || privatePathValue.isBlank()) {
            privatePathValue = System.getenv("FABRICPACKER_SIGNING_PRIVATE_KEY");
        }
        String publicPathValue = System.getProperty("fabricpacker.signing.publicKey");
        if (publicPathValue == null || publicPathValue.isBlank()) {
            publicPathValue = System.getenv("FABRICPACKER_SIGNING_PUBLIC_KEY");
        }
        if ((privatePathValue == null || privatePathValue.isBlank())
                && (publicPathValue == null || publicPathValue.isBlank())
                && Boolean.getBoolean("fabricpacker.signing.generate")) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
                KeyPair pair = generator.generateKeyPair();
                return new SigningMaterial(pair.getPrivate(), pair.getPublic().getEncoded(),
                        pair.getPrivate().getEncoded());
            } catch (Exception failure) {
                throw new IOException("Could not generate ephemeral Ed25519 signing key", failure);
            }
        }
        if (privatePathValue == null || privatePathValue.isBlank()
                || publicPathValue == null || publicPathValue.isBlank()) {
            throw new IOException("Ed25519 signing requires -Dfabricpacker.signing.privateKey=<PKCS8> "
                    + "and -Dfabricpacker.signing.publicKey=<X509>, or -Dfabricpacker.signing.generate=true");
        }
        Path privatePath = Path.of(privatePathValue).toAbsolutePath().normalize();
        Path outputDirectory = output.toAbsolutePath().normalize().getParent();
        if (outputDirectory != null && (privatePath.equals(outputDirectory)
                || privatePath.startsWith(outputDirectory))) {
            throw new IOException("Private signing key must be outside the build output directory");
        }
        byte[] privateEncoded = Files.readAllBytes(privatePath);
        byte[] publicEncoded = Files.readAllBytes(Path.of(publicPathValue).toAbsolutePath().normalize());
        try {
            PrivateKey privateKey = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(privateEncoded));
            PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(publicEncoded));
            Signature check = Signature.getInstance("Ed25519");
            byte[] challenge = "fabricpacker-ed25519-check".getBytes(StandardCharsets.UTF_8);
            check.initSign(privateKey);
            check.update(challenge);
            byte[] signed = check.sign();
            check.initVerify(publicKey);
            check.update(challenge);
            boolean matches = check.verify(signed);
            wipe(challenge);
            wipe(signed);
            if (!matches) throw new IOException("Ed25519 private and public keys do not match");
            return new SigningMaterial(privateKey, publicEncoded, privateEncoded);
        } catch (IOException failure) {
            wipe(privateEncoded);
            wipe(publicEncoded);
            throw failure;
        } catch (Exception failure) {
            wipe(privateEncoded);
            wipe(publicEncoded);
            throw new IOException("Could not read Ed25519 signing keys", failure);
        }
    }

    private static byte[] read(JarFile jar, JarEntry entry) throws IOException {
        try (InputStream stream = jar.getInputStream(entry)) {
            return stream.readAllBytes();
        }
    }

    private static byte[] sha256(byte[] data) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception failure) {
            throw new IOException("SHA-256 is unavailable", failure);
        }
    }

    private static void wipeMap(Map<String, byte[]> values) {
        for (byte[] value : values.values()) wipe(value);
        values.clear();
    }

    private static void wipeHashMap(Map<String, byte[]> values) {
        for (byte[] value : values.values()) wipe(value);
        values.clear();
    }

    private static void wipe(byte[] value) {
        if (value != null) java.util.Arrays.fill(value, (byte) 0);
    }

    private static void wipe(int[] value) {
        if (value != null) java.util.Arrays.fill(value, 0);
    }

    private static void requireFile(Path path, String description) throws IOException {
        if (!Files.isRegularFile(path)) throw new IOException(description + " not found: " + path);
    }

    private record Blob(String path, int type, int clearLength, int compressedLength,
            int paddingLength, byte[] hash, byte[] blob, long offset) {
    }

    private record SigningMaterial(PrivateKey privateKey, byte[] publicEncoded, byte[] privateEncoded) {
    }
}
