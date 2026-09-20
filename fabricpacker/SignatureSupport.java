package fabricpacker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Build-time Ed25519 archive signatures. This class is never copied to a packed mod. */
final class SignatureSupport {
    static final int MAGIC = 0x46505331; // FPS1
    static final int VERSION = 1;
    static final int RESOURCE = 0;
    static final int PAYLOAD_INDEX = 1;
    static final int HASH_LENGTH = 32;
    static final int PAYLOAD_HEADER_LENGTH = 22;
    // Matches PackedClassLoader.MAX_ENTRIES: a mod with more signed entries than
    // this could never be loaded anyway, so reject it at build time too.
    static final int MAX_ENTRIES = 100_000;

    private SignatureSupport() {
    }

    static byte[] create(Map<String, byte[]> entries, String payloadResource,
            PrivateKey privateKey) throws IOException {
        List<Record> records = records(entries, payloadResource);
        byte[] canonical = canonical(records);
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(canonical);
            byte[] signature = signer.sign();
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(canonical.length + signature.length + 4);
            bytes.write(canonical);
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(signature.length);
            output.write(signature);
            output.flush();
            java.util.Arrays.fill(signature, (byte) 0);
            return bytes.toByteArray();
        } catch (Exception failure) {
            throw new IOException("Could not create Ed25519 archive signature", failure);
        } finally {
            java.util.Arrays.fill(canonical, (byte) 0);
            wipeRecords(records);
        }
    }

    static boolean verify(Map<String, byte[]> entries, String signatureResource,
            byte[] publicKey, String payloadResource) {
        byte[] blob = entries.get(signatureResource);
        if (blob == null || publicKey == null) return false;
        try {
            return verifyBlob(entries, blob, publicKey, payloadResource);
        } catch (Exception ignored) {
            return false;
        }
    }

    static SelfTestResult selfTest(Map<String, byte[]> original, String signatureResource,
            byte[] publicKey, String payloadResource) throws IOException {
        if (!verify(original, signatureResource, publicKey, payloadResource)) {
            throw new IOException("Ed25519 self-test failed for valid archive");
        }
        Map<String, byte[]> payload = copy(original);
        flipFirst(payload.get(payloadResource));
        boolean payloadRejected = !verify(payload, signatureResource, publicKey, payloadResource);
        wipeMap(payload);

        Map<String, byte[]> loader = copy(original);
        String loaderPath = loader.keySet().stream()
                .filter(path -> path.startsWith("fabricpacker/") && path.endsWith(".class"))
                .findFirst().orElseThrow(() -> new IOException("No signed loader class found"));
        flipFirst(loader.get(loaderPath));
        boolean loaderRejected = !verify(loader, signatureResource, publicKey, payloadResource);
        wipeMap(loader);

        Map<String, byte[]> index = copy(original);
        byte[] indexPayload = index.get(payloadResource);
        if (indexPayload == null || indexPayload.length <= PAYLOAD_HEADER_LENGTH) {
            throw new IOException("Signed payload has no mutable index bytes");
        }
        indexPayload[PAYLOAD_HEADER_LENGTH] ^= 1;
        boolean indexRejected = !verify(index, signatureResource, publicKey, payloadResource);
        wipeMap(index);

        Map<String, byte[]> missing = copy(original);
        missing.remove(signatureResource);
        boolean missingRejected = !verify(missing, signatureResource, publicKey, payloadResource);
        wipeMap(missing);

        byte[] wrongKey = new byte[publicKey.length];
        System.arraycopy(publicKey, 0, wrongKey, 0, publicKey.length);
        wrongKey[wrongKey.length - 1] ^= 1;
        boolean wrongKeyRejected = !verify(original, signatureResource, wrongKey, payloadResource);
        java.util.Arrays.fill(wrongKey, (byte) 0);

        if (!payloadRejected || !loaderRejected || !indexRejected || !missingRejected || !wrongKeyRejected) {
            throw new IOException("Ed25519 tamper self-test failed");
        }
        return new SelfTestResult(true, payloadRejected, loaderRejected, indexRejected,
                missingRejected, wrongKeyRejected);
    }

    private static boolean verifyBlob(Map<String, byte[]> entries, byte[] blob,
            byte[] publicKey, String payloadResource) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(blob));
        int magic = input.readInt();
        int version = input.readInt();
        if (magic != MAGIC || version != VERSION) return false;
        int count = input.readInt();
        if (count < 2 || count > MAX_ENTRIES) return false;
        ByteArrayOutputStream canonicalBytes = new ByteArrayOutputStream(blob.length);
        DataOutputStream canonical = new DataOutputStream(canonicalBytes);
        canonical.writeInt(magic);
        canonical.writeInt(version);
        canonical.writeInt(count);
        boolean payloadSeen = false;
        boolean indexSeen = false;
        boolean loaderSeen = false;
        for (int i = 0; i < count; i++) {
            int kind = input.readUnsignedByte();
            String path = readString(input);
            long offset = input.readLong();
            int length = input.readInt();
            byte[] expected = input.readNBytes(HASH_LENGTH);
            if (expected.length != HASH_LENGTH || length < 0 || path.isEmpty()) return false;
            canonical.writeByte(kind);
            writeString(canonical, path);
            canonical.writeLong(offset);
            canonical.writeInt(length);
            canonical.write(expected);
            byte[] actual = entries.get(path);
            if (kind == RESOURCE) {
                if (offset != -1L || actual == null || actual.length != length) return false;
                if (!MessageDigestCompat.equal(expected, digest(actual))) return false;
                if (path.equals(payloadResource)) payloadSeen = true;
                if (path.startsWith("fabricpacker/") && path.endsWith(".class")) loaderSeen = true;
            } else if (kind == PAYLOAD_INDEX) {
                if (!path.equals(payloadResource) || actual == null || offset < 0
                        || length < 16 || offset > actual.length - length) return false;
                byte[] index = java.util.Arrays.copyOfRange(actual, (int) offset, (int) offset + length);
                boolean valid = MessageDigestCompat.equal(expected, digest(index));
                java.util.Arrays.fill(index, (byte) 0);
                if (!valid) return false;
                indexSeen = true;
            } else {
                return false;
            }
            java.util.Arrays.fill(expected, (byte) 0);
        }
        int signatureLength = input.readInt();
        if (signatureLength < 32 || signatureLength > 512) return false;
        byte[] signature = input.readNBytes(signatureLength);
        if (signature.length != signatureLength || input.available() != 0
                || !payloadSeen || !indexSeen || !loaderSeen) return false;
        canonical.flush();
        PublicKey key = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(publicKey));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(canonicalBytes.toByteArray());
        boolean valid = verifier.verify(signature);
        java.util.Arrays.fill(signature, (byte) 0);
        // canonicalBytes holds only public hashes and lengths; there is nothing
        // secret to wipe, and toByteArray() would only clear a throwaway copy.
        return valid;
    }

    private static List<Record> records(Map<String, byte[]> entries, String payloadResource) throws IOException {
        List<String> paths = new ArrayList<>(entries.keySet());
        paths.sort(Comparator.naturalOrder());
        List<Record> result = new ArrayList<>();
        for (String path : paths) {
            byte[] value = entries.get(path);
            if (value == null) throw new IOException("Null archive entry: " + path);
            result.add(new Record(RESOURCE, path, -1L, value.length, digest(value)));
        }
        byte[] payload = entries.get(payloadResource);
        if (payload == null || payload.length < PAYLOAD_HEADER_LENGTH) {
            throw new IOException("Signed payload is missing or truncated");
        }
        int indexLength = readInt(payload, 18);
        if (indexLength < 16 || PAYLOAD_HEADER_LENGTH + indexLength > payload.length) {
            throw new IOException("Signed payload index is invalid");
        }
        byte[] index = java.util.Arrays.copyOfRange(payload, PAYLOAD_HEADER_LENGTH,
                PAYLOAD_HEADER_LENGTH + indexLength);
        result.add(new Record(PAYLOAD_INDEX, payloadResource, PAYLOAD_HEADER_LENGTH,
                indexLength, digest(index)));
        java.util.Arrays.fill(index, (byte) 0);
        return result;
    }

    private static byte[] canonical(List<Record> records) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(MAGIC);
        output.writeInt(VERSION);
        output.writeInt(records.size());
        for (Record record : records) {
            output.writeByte(record.kind);
            writeString(output, record.path);
            output.writeLong(record.offset);
            output.writeInt(record.length);
            output.write(record.hash);
        }
        output.flush();
        return bytes.toByteArray();
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > 1_000_000) throw new IOException("Invalid signature path");
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new IOException("Truncated signature path");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static int readInt(byte[] data, int offset) throws IOException {
        if (offset < 0 || offset + 4 > data.length) throw new IOException("Truncated payload");
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static byte[] digest(byte[] value) throws IOException {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception failure) {
            throw new IOException("SHA-256 unavailable", failure);
        }
    }

    private static Map<String, byte[]> copy(Map<String, byte[]> original) {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : original.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().clone());
        }
        return copy;
    }

    private static void flipFirst(byte[] value) throws IOException {
        if (value == null || value.length == 0) throw new IOException("Cannot tamper with empty entry");
        value[0] ^= 1;
    }

    private static void wipeMap(Map<String, byte[]> values) {
        for (byte[] value : values.values()) java.util.Arrays.fill(value, (byte) 0);
        values.clear();
    }

    private static void wipeRecords(List<Record> records) {
        for (Record record : records) java.util.Arrays.fill(record.hash, (byte) 0);
    }

    record SelfTestResult(boolean valid, boolean payloadRejected, boolean loaderRejected,
            boolean indexRejected, boolean missingRejected, boolean wrongKeyRejected) {
    }

    private record Record(int kind, String path, long offset, int length, byte[] hash) {
    }

    private static final class MessageDigestCompat {
        private MessageDigestCompat() {
        }

        static boolean equal(byte[] left, byte[] right) {
            boolean valid = left != null && right != null
                    && java.security.MessageDigest.isEqual(left, right);
            if (right != null) java.util.Arrays.fill(right, (byte) 0);
            return valid;
        }
    }
}
