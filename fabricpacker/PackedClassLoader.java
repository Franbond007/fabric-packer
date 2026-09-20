package fabricpacker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.JarURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.spec.X509EncodedKeySpec;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Loads classes and resources from one authenticated in-memory container.
 *
 * The container hides protected names and offsets. It is intended to make static
 * extraction harder; a client that executes the mod can still inspect live bytes.
 */
public final class PackedClassLoader extends ClassLoader implements AutoCloseable {
    private static final int VERSION = A0.f();
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int HASH_LENGTH = 32;
    private static final int HEADER_LENGTH = 4 + 2 + NONCE_LENGTH + 4;
    private static final int ENTRY_TYPE_CLASS = 1;
    private static final int ENTRY_TYPE_RESOURCE = 2;
    private static final int MAX_PADDING = 8192;
    private static final int MAX_CLEAR_LENGTH = 256 * 1024 * 1024;
    private static final String PAYLOAD_RESOURCE = A0.e(2);
    private static final String SIGNATURE_RESOURCE = A0.e(31);
    private static final byte[] SIGNATURE = A0.c();
    private static final byte[] INDEX_TAG = A0.d();
    private static final int MAX_ENTRIES = 100_000;
    private static final int MAX_NAME_LENGTH = 1_000_000;

    private final ClassLoader resourceLoader;
    private final Map<String, Entry> entries;
    private final long keyHandle;
    private byte[] container;
    private final URL rootUrl;
    private volatile boolean closed;

    public PackedClassLoader(ClassLoader parent, ClassLoader resourceLoader) throws IOException {
        super(parent);
        this.resourceLoader = resourceLoader;
        Guard.check();
        A0.b(resourceLoader);
        verifySignedAssets(resourceLoader);
        this.container = readRequired(resourceLoader, PAYLOAD_RESOURCE);
        this.keyHandle = deriveKeyHandle();
        this.entries = parseIndex(container);
        try {
            this.rootUrl = new URL(null, "fabricpacked://classes/", new MemoryUrlHandler(this));
        } catch (IOException failure) {
            close();
            throw new IOException(A0.e(24), failure);
        }
    }

    /**
     * Derives the payload key inside the native core. The Java-visible material,
     * salt and info are combined with the binary's baked mask natively; the real
     * AES key never touches the Java heap and there is no in-process fallback.
     */
    private static long deriveKeyHandle() throws IOException {
        byte[] material = A0.a();
        byte[] salt = A0.h();
        byte[] info = A0.i();
        try {
            long handle = N0.nk(material, salt, info);
            if (handle == 0) throw new IOException(A0.e(25));
            return handle;
        } catch (RuntimeException failure) {
            throw new IOException(A0.e(25), failure);
        } finally {
            wipe(material);
            wipe(salt);
            wipe(info);
        }
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        String path = name.replace('.', '/') + ".class";
        Entry entry = entries.get(path);
        if (entry == null) throw new ClassNotFoundException(name);
        byte[] data = null;
        try {
            data = readBlob(path, entry);
            return defineClass(name, data, 0, data.length);
        } catch (Exception failure) {
            throw new ClassNotFoundException(A0.e(17) + name, failure);
        } finally {
            wipe(data);
        }
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        String path = normalizeResourceName(name);
        Entry entry = entries.get(path);
        if (entry != null) {
            try {
                return new WipingInputStream(readBlob(path, entry));
            } catch (IOException failure) {
                throw new IllegalStateException(A0.e(15) + path, failure);
            }
        }
        return resourceLoader.getResourceAsStream(name);
    }

    @Override
    public URL getResource(String name) {
        String path = normalizeResourceName(name);
        if (entries.containsKey(path)) {
            try {
                return new URL(rootUrl, path);
            } catch (IOException failure) {
                throw new IllegalStateException(A0.e(16), failure);
            }
        }
        return resourceLoader.getResource(name);
    }

    @Override
    public Enumeration<URL> findResources(String name) throws IOException {
        String path = normalizeResourceName(name);
        List<URL> urls = new ArrayList<>(1);
        if (entries.containsKey(path) || hasEntryPrefix(path)) {
            try {
                urls.add(new URL(rootUrl, path));
            } catch (IOException ignored) {
                // Index paths are validated; a malformed URL must never break enumeration.
            }
        }
        return Collections.enumeration(urls);
    }

    private boolean hasEntryPrefix(String path) {
        if (entries.isEmpty()) return false;
        if (path.isEmpty()) return true;
        String prefix = path.endsWith("/") ? path : path + "/";
        for (String candidate : entries.keySet()) {
            if (candidate.startsWith(prefix)) return true;
        }
        return false;
    }

    URL rootUrl() {
        return rootUrl;
    }

    InputStream openResource(String name) throws IOException {
        String path = normalizeResourceName(name);
        Entry entry = entries.get(path);
        if (entry == null) throw new FileNotFoundException(path);
        return new WipingInputStream(readBlob(path, entry));
    }

    private void verifySignedAssets(ClassLoader loader) throws IOException {
        byte[] blob = null;
        byte[] publicKey = null;
        byte[] signature = null;
        byte[] canonicalBytes = null;
        try {
            blob = readRequired(loader, SIGNATURE_RESOURCE);
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(blob));
            int magic = input.readInt();
            int format = input.readInt();
            if (magic != 0x46505331 || format != 1) throw new IOException(A0.e(33));
            int count = input.readInt();
            if (count < 2 || count > MAX_ENTRIES) throw new IOException(A0.e(33));
            ByteArrayOutputStream canonical = new ByteArrayOutputStream(blob.length);
            DataOutputStream canonicalOutput = new DataOutputStream(canonical);
            canonicalOutput.writeInt(magic);
            canonicalOutput.writeInt(format);
            canonicalOutput.writeInt(count);
            boolean payloadSeen = false;
            boolean indexSeen = false;
            boolean loaderSeen = false;
            for (int i = 0; i < count; i++) {
                int kind = input.readUnsignedByte();
                String path = readString(input);
                long offset = input.readLong();
                int length = input.readInt();
                byte[] expected = input.readNBytes(HASH_LENGTH);
                if (expected.length != HASH_LENGTH || length < 0 || path.isEmpty()) {
                    wipe(expected);
                    throw new IOException(A0.e(33));
                }
                canonicalOutput.writeByte(kind);
                writeSignedString(canonicalOutput, path);
                canonicalOutput.writeLong(offset);
                canonicalOutput.writeInt(length);
                canonicalOutput.write(expected);
                byte[] actual = readSignedBytes(loader, path);
                if (kind == 0) {
                    if (offset != -1L || actual.length != length
                            || !MessageDigest.isEqual(expected, sha256(actual))) {
                        wipe(actual);
                        wipe(expected);
                        throw new IOException(A0.e(34) + path);
                    }
                    if (path.equals(PAYLOAD_RESOURCE)) payloadSeen = true;
                    if (path.startsWith("fabricpacker/") && path.endsWith(".class")) loaderSeen = true;
                } else if (kind == 1) {
                    if (!path.equals(PAYLOAD_RESOURCE) || offset < 0
                            || length < 16 || offset > actual.length - length) {
                        wipe(actual);
                        wipe(expected);
                        throw new IOException(A0.e(33));
                    }
                    byte[] index = copy(actual, (int) offset, length);
                    boolean valid = MessageDigest.isEqual(expected, sha256(index));
                    wipe(index);
                    if (!valid) {
                        wipe(actual);
                        wipe(expected);
                        throw new IOException(A0.e(34) + path);
                    }
                    indexSeen = true;
                } else {
                    wipe(actual);
                    wipe(expected);
                    throw new IOException(A0.e(33));
                }
                wipe(actual);
                wipe(expected);
            }
            int signatureLength = input.readInt();
            if (signatureLength < 32 || signatureLength > 512) throw new IOException(A0.e(33));
            signature = input.readNBytes(signatureLength);
            if (signature.length != signatureLength || input.available() != 0
                    || !payloadSeen || !indexSeen || !loaderSeen) {
                throw new IOException(A0.e(33));
            }
            canonicalOutput.flush();
            canonicalBytes = canonical.toByteArray();
            publicKey = A0.g();
            java.security.PublicKey key = KeyFactory.getInstance(A0.e(32))
                    .generatePublic(new X509EncodedKeySpec(publicKey));
            Signature verifier = Signature.getInstance(A0.e(32));
            verifier.initVerify(key);
            verifier.update(canonicalBytes);
            if (!verifier.verify(signature)) throw new IOException(A0.e(35));
        } catch (IOException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IOException(A0.e(35), failure);
        } finally {
            wipe(blob);
            wipe(publicKey);
            wipe(signature);
            wipe(canonicalBytes);
        }
    }

    private static void writeSignedString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static byte[] readSignedBytes(ClassLoader loader, String path) throws IOException {
        URL signatureUrl = loader.getResource(SIGNATURE_RESOURCE);
        if (signatureUrl != null) {
            URLConnection connection = signatureUrl.openConnection();
            if (connection instanceof JarURLConnection jarConnection) {
                jarConnection.setUseCaches(false);
                try (JarFile jar = jarConnection.getJarFile()) {
                    JarEntry entry = jar.getJarEntry(path);
                    if (entry == null) throw new FileNotFoundException(path);
                    try (InputStream input = jar.getInputStream(entry)) {
                        return input.readAllBytes();
                    }
                }
            }
        }
        try {
            URL location = PackedClassLoader.class.getProtectionDomain().getCodeSource().getLocation();
            if (location != null && "file".equalsIgnoreCase(location.getProtocol())
                    && location.getPath().toLowerCase(java.util.Locale.ROOT).endsWith(".jar")) {
                try (JarFile jar = new JarFile(java.nio.file.Path.of(location.toURI()).toFile())) {
                    JarEntry entry = jar.getJarEntry(path);
                    if (entry == null) throw new FileNotFoundException(path);
                    try (InputStream input = jar.getInputStream(entry)) {
                        return input.readAllBytes();
                    }
                }
            }
        } catch (java.net.URISyntaxException ignored) {
        }
        return readRequired(loader, path);
    }

    private Map<String, Entry> parseIndex(byte[] payload) throws IOException {
        if (payload.length < HEADER_LENGTH + 16) throw new IOException(A0.e(3));
        for (int i = 0; i < SIGNATURE.length; i++) {
            if (payload[i] != SIGNATURE[i]) throw new IOException(A0.e(4));
        }
        int version = ((payload[4] & 0xff) << 8) | (payload[5] & 0xff);
        if (version != VERSION) throw new IOException(A0.e(5) + version);
        int indexLength = readPackedInt(payload, 18);
        int indexOffset = HEADER_LENGTH;
        if (indexLength < 16 || indexOffset + indexLength > payload.length) {
            throw new IOException(A0.e(6));
        }
        byte[] index = null;
        try {
            byte[] nonce = copy(payload, 6, NONCE_LENGTH);
            try {
                index = openCipher(indexOffset, indexLength, nonce, INDEX_TAG);
            } finally {
                wipe(nonce);
            }
            return parseIndexBytes(index, indexOffset + indexLength, payload.length);
        } finally {
            wipe(index);
        }
    }

    private Map<String, Entry> parseIndexBytes(byte[] index, int dataStart, int payloadLength)
            throws IOException {
        Map<String, Entry> result = new HashMap<>();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(index))) {
            int count = input.readInt();
            if (count < 0 || count > MAX_ENTRIES) throw new IOException(A0.e(7));
            for (int i = 0; i < count; i++) {
                String path = readString(input);
                int type = input.readUnsignedByte();
                long offset = input.readLong();
                int blobLength = input.readInt();
                int clearLength = input.readInt();
                int compressedLength = input.readInt();
                int paddingLength = input.readInt();
                byte[] hash = input.readNBytes(HASH_LENGTH);
                if (hash.length != HASH_LENGTH || !validEntryPath(path)
                        || (type != ENTRY_TYPE_CLASS && type != ENTRY_TYPE_RESOURCE)
                        || offset < dataStart || blobLength < NONCE_LENGTH + 16
                        || clearLength < 0 || clearLength > MAX_CLEAR_LENGTH
                        || compressedLength < 1 || compressedLength > MAX_CLEAR_LENGTH
                        || paddingLength < 0 || paddingLength > MAX_PADDING
                        || blobLength != NONCE_LENGTH + compressedLength + paddingLength + 16
                        || offset > payloadLength - blobLength
                        || result.put(path, new Entry(offset, type, blobLength, clearLength,
                        compressedLength, paddingLength, hash)) != null) {
                    throw new IOException(A0.e(9) + path);
                }
            }
            int exclusionCount = input.readInt();
            if (exclusionCount < 0 || exclusionCount > MAX_ENTRIES) {
                throw new IOException(A0.e(8));
            }
            for (int i = 0; i < exclusionCount; i++) {
                readString(input);
                readString(input);
            }
            if (input.available() != 0) throw new IOException(A0.e(10));
        }
        if (result.isEmpty()) throw new IOException(A0.e(11));
        return result;
    }

    private byte[] readBlob(String path, Entry entry) throws IOException {
        ensureOpen();
        if (entry.offset < 0 || entry.blobLength < NONCE_LENGTH + 16
                || entry.offset > container.length - entry.blobLength) {
            throw new IOException(A0.e(12) + path);
        }
        byte[] nonce = copy(container, (int) entry.offset, NONCE_LENGTH);
        byte[] packed = null;
        byte[] compressed = null;
        byte[] clear = null;
        try {
            byte[] aad = tagData(path, entry.type, entry.clearLength, entry.compressedLength,
                    entry.paddingLength, entry.hash);
            try {
                packed = openCipher((int) entry.offset + NONCE_LENGTH, entry.blobLength - NONCE_LENGTH,
                        nonce, aad);
            } finally {
                wipe(aad);
            }
            if (packed.length != entry.compressedLength + entry.paddingLength) {
                throw new IOException(A0.e(12) + path);
            }
            compressed = copy(packed, 0, entry.compressedLength);
            clear = inflate(compressed, entry.clearLength);
            byte[] actualHash = sha256(clear);
            boolean valid = clear.length == entry.clearLength
                    && MessageDigest.isEqual(actualHash, entry.hash);
            wipe(actualHash);
            if (!valid) {
                wipe(clear);
                throw new IOException(A0.e(13) + path);
            }
            return clear;
        } catch (IOException failure) {
            wipe(clear);
            throw failure;
        } finally {
            wipe(compressed);
            wipe(packed);
            wipe(nonce);
        }
    }

    private byte[] openCipher(int cipherOffset, int cipherLength, byte[] nonce, byte[] aad)
            throws IOException {
        try {
            return N0.nd(keyHandle, nonce, aad, container, cipherOffset, cipherLength);
        } catch (RuntimeException failure) {
            throw new IOException(A0.e(14), failure);
        }
    }

    private static byte[] tagData(String path, int type, int clearLength, int compressedLength,
            int paddingLength, byte[] hash) throws IOException {
        byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(pathBytes.length + 80);
        java.io.DataOutputStream output = new java.io.DataOutputStream(bytes);
        output.writeInt(0x46504144);
        output.writeShort(VERSION);
        output.writeInt(SIGNATURE.length);
        output.write(SIGNATURE);
        output.writeInt(INDEX_TAG.length);
        output.write(INDEX_TAG);
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

    private static byte[] inflate(byte[] compressed, int expectedLength) throws IOException {
        if (expectedLength < 0 || expectedLength > MAX_CLEAR_LENGTH) {
            throw new IOException(A0.e(12));
        }
        Inflater inflater = new Inflater();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(expectedLength, 8192));
        byte[] buffer = new byte[8192];
        try {
            inflater.setInput(compressed);
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    if (bytes.size() > expectedLength - count) throw new IOException(A0.e(12));
                    bytes.write(buffer, 0, count);
                } else {
                    throw new IOException(A0.e(12));
                }
            }
            if (bytes.size() != expectedLength || inflater.getRemaining() != 0) {
                throw new IOException(A0.e(12));
            }
            return bytes.toByteArray();
        } catch (DataFormatException failure) {
            throw new IOException(A0.e(12), failure);
        } finally {
            inflater.end();
            wipe(buffer);
        }
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAX_NAME_LENGTH) throw new IOException(A0.e(18));
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new IOException(A0.e(19));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static boolean validEntryPath(String path) {
        return path != null && !path.isEmpty() && !path.startsWith("/")
                && !path.contains("\\") && !path.contains("..") && path.indexOf('\0') < 0;
    }

    private static String normalizeResourceName(String name) {
        if (name == null) return "";
        return name.startsWith("/") ? name.substring(1) : name;
    }

    private static byte[] readRequired(ClassLoader loader, String resource) throws IOException {
        try (InputStream input = loader.getResourceAsStream(resource)) {
            if (input == null) throw new FileNotFoundException(resource);
            return input.readAllBytes();
        }
    }

    private static int readPackedInt(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static byte[] copy(byte[] source, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, offset, result, 0, length);
        return result;
    }

    private static byte[] sha256(byte[] data) throws IOException {
        try {
            return MessageDigest.getInstance(A0.e(1)).digest(data);
        } catch (Exception failure) {
            throw new IOException(A0.e(22), failure);
        }
    }

    private static void wipe(byte[] data) {
        if (data != null) java.util.Arrays.fill(data, (byte) 0);
    }

    private void ensureOpen() throws IOException {
        if (closed || container == null) throw new IOException(A0.e(20));
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            if (keyHandle != 0) N0.nx(keyHandle);
            wipe(container);
            container = null;
            for (Entry entry : entries.values()) wipe(entry.hash);
            entries.clear();
        }
    }

    private record Entry(long offset, int type, int blobLength, int clearLength,
            int compressedLength, int paddingLength, byte[] hash) {
    }

    static final class MemoryUrlHandler extends URLStreamHandler {
        private final PackedClassLoader owner;

        MemoryUrlHandler(PackedClassLoader owner) {
            this.owner = owner;
        }

        @Override
        protected URLConnection openConnection(URL url) {
            return new MemoryURLConnection(url, owner);
        }
    }

    static final class MemoryURLConnection extends URLConnection {
        private final PackedClassLoader owner;

        MemoryURLConnection(URL url, PackedClassLoader owner) {
            super(url);
            this.owner = owner;
        }

        @Override
        public void connect() {
            connected = true;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            connect();
            return owner.openResource(url.getPath());
        }
    }

    static final class WipingInputStream extends ByteArrayInputStream {
        private boolean closed;

        WipingInputStream(byte[] bytes) {
            super(bytes);
        }

        @Override
        public synchronized int read() {
            if (closed) return -1;
            int value = super.read();
            if (pos >= count) close();
            return value;
        }

        @Override
        public synchronized int read(byte[] bytes, int offset, int length) {
            if (closed) return -1;
            int value = super.read(bytes, offset, length);
            if (pos >= count) close();
            return value;
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                closed = true;
                wipe(buf);
                pos = count = 0;
            }
        }
    }
}
