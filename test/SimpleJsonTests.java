package fabricpacker;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

final class SimpleJsonTests {
    private SimpleJsonTests() {
    }

    static void testParseObject() throws IOException {
        Object parsed = SimpleJson.parse("{\"a\":1,\"b\":[true,false,null],\"c\":{\"d\":\"x\"}}", "t");
        Map<?, ?> map = (Map<?, ?>) parsed;
        TestRunner.assertEquals(new BigDecimal("1"), map.get("a"));
        List<?> list = (List<?>) map.get("b");
        TestRunner.assertEquals(Boolean.TRUE, list.get(0));
        TestRunner.assertEquals(Boolean.FALSE, list.get(1));
        TestRunner.assertEquals(null, list.get(2));
        Map<?, ?> nested = (Map<?, ?>) map.get("c");
        TestRunner.assertEquals("x", nested.get("d"));
    }

    static void testParseNumbers() throws IOException {
        TestRunner.assertEquals(new BigDecimal("12.5"), SimpleJson.parse("12.5", "t"));
        TestRunner.assertEquals(new BigDecimal("1e2"), SimpleJson.parse("1e2", "t"));
        TestRunner.assertEquals(new BigDecimal("-3"), SimpleJson.parse("-3", "t"));
    }

    static void testParseEscapes() throws IOException {
        String json = "\"\\u00e4\\n\\t\\\"\\/\"";
        TestRunner.assertEquals("\u00e4\n\t\"/", SimpleJson.parse(json, "t"));
    }

    static void testParseStringOnly() throws IOException {
        TestRunner.assertEquals("value", SimpleJson.parse("\"value\"", "t"));
    }

    static void testWriteRoundTrip() throws IOException {
        String json = "{\"a\":[1,2.5,true,null,\"x\\ny\"]}";
        Object parsed = SimpleJson.parse(json, "t");
        TestRunner.assertEquals(json, SimpleJson.write(parsed).trim());
    }

    static void testWriteEscapesControlChar() throws IOException {
        TestRunner.assertEquals("\"a\\u0001b\"", SimpleJson.write("a\u0001b").trim());
    }

    static void testTrailingDataFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("{} {}", "t"));
    }

    static void testInvalidEscapeFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("\"\\q\"", "t"));
    }

    static void testUnterminatedStringFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("\"abc", "t"));
    }

    static void testInvalidLiteralFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("nul", "t"));
    }

    static void testBadExponentFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("1e", "t"));
    }

    static void testBadFractionFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("1.", "t"));
    }

    static void testShortUnicodeEscapeFails() {
        TestRunner.assertThrows(IOException.class, () -> SimpleJson.parse("\"\\u00e\"", "t"));
    }
}
