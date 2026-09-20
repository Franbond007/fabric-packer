package fabricpacker;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

final class SignatureSupportTests {
    private static final String PAYLOAD = "fabricpacker/pTestPayload.dat";
    private static final String SIGNATURE = "fabricpacker/sTestSignature.sig";

    private SignatureSupportTests() {
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        return generator.generateKeyPair();
    }

    private static byte[] samplePayload() {
        byte[] payload = new byte[SignatureSupport.PAYLOAD_HEADER_LENGTH + 16];
        byte[] index = new byte[16];
        new SecureRandom().nextBytes(index);
        System.arraycopy(index, 0, payload, SignatureSupport.PAYLOAD_HEADER_LENGTH, index.length);
        int indexLength = 16;
        payload[18] = (byte) (indexLength >>> 24);
        payload[19] = (byte) (indexLength >>> 16);
        payload[20] = (byte) (indexLength >>> 8);
        payload[21] = (byte) indexLength;
        return payload;
    }

    private static Map<String, byte[]> archive(KeyPair pair) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("assets/logo.png", new byte[]{1, 2, 3, 4});
        entries.put("fabricpacker/FakeLoader.class", "fake loader".getBytes(StandardCharsets.UTF_8));
        entries.put(PAYLOAD, samplePayload());
        byte[] signed = SignatureSupport.create(entries, PAYLOAD, pair.getPrivate());
        entries.put(SIGNATURE, signed);
        return entries;
    }

    static void testCreateAndVerify() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        TestRunner.assertTrue(SignatureSupport.verify(entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD));
    }

    static void testPayloadTamperRejected() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        entries.get(PAYLOAD)[0] ^= 1;
        TestRunner.assertFalse(SignatureSupport.verify(entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD));
    }

    static void testLoaderTamperRejected() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        entries.get("fabricpacker/FakeLoader.class")[0] ^= 1;
        TestRunner.assertFalse(SignatureSupport.verify(entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD));
    }

    static void testIndexTamperRejected() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        entries.get(PAYLOAD)[SignatureSupport.PAYLOAD_HEADER_LENGTH] ^= 1;
        TestRunner.assertFalse(SignatureSupport.verify(entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD));
    }

    static void testMissingSignatureRejected() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        entries.remove(SIGNATURE);
        TestRunner.assertFalse(SignatureSupport.verify(entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD));
    }

    static void testWrongKeyRejected() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        byte[] wrongKey = pair.getPublic().getEncoded().clone();
        wrongKey[wrongKey.length - 1] ^= 1;
        TestRunner.assertFalse(SignatureSupport.verify(entries, SIGNATURE, wrongKey, PAYLOAD));
    }

    static void testSelfTest() throws Exception {
        KeyPair pair = keyPair();
        Map<String, byte[]> entries = archive(pair);
        SignatureSupport.SelfTestResult result = SignatureSupport.selfTest(
                entries, SIGNATURE, pair.getPublic().getEncoded(), PAYLOAD);
        TestRunner.assertTrue(result.valid());
        TestRunner.assertTrue(result.payloadRejected());
        TestRunner.assertTrue(result.loaderRejected());
        TestRunner.assertTrue(result.indexRejected());
        TestRunner.assertTrue(result.missingRejected());
        TestRunner.assertTrue(result.wrongKeyRejected());
    }
}