package fabricpacker;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small dependency-free JSON reader/writer for Fabric metadata and packer config. */
final class SimpleJson {
    private SimpleJson() {
    }

    static Object parse(String text, String source) throws IOException {
        return new Parser(text, source).document();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value, String message) throws IOException {
        if (!(value instanceof Map<?, ?>)) throw new IOException(message);
        return (Map<String, Object>) value;
    }

    static String write(Object value) throws IOException {
        StringBuilder result = new StringBuilder();
        writeValue(value, result);
        return result.append('\n').toString();
    }

    private static void writeValue(Object value, StringBuilder out) throws IOException {
        if (value == null) out.append("null");
        else if (value instanceof String) writeString((String) value, out);
        else if (value instanceof Boolean || value instanceof Number) out.append(value);
        else if (value instanceof Map<?, ?>) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String)) throw new IOException("JSON object key is not a string");
                if (!first) out.append(',');
                first = false;
                writeString((String) entry.getKey(), out);
                out.append(':');
                writeValue(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof List<?>) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) out.append(',');
                first = false;
                writeValue(item, out);
            }
            out.append(']');
        } else throw new IOException("Unsupported JSON value: " + value.getClass().getName());
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String text;
        private final String source;
        private int offset;

        private Parser(String text, String source) {
            this.text = text;
            this.source = source;
        }

        private Object document() throws IOException {
            Object result = value();
            whitespace();
            if (offset != text.length()) fail("trailing data");
            return result;
        }

        private Object value() throws IOException {
            whitespace();
            if (offset >= text.length()) fail("missing value");
            return switch (text.charAt(offset)) {
                case '{' -> objectValue();
                case '[' -> arrayValue();
                case '"' -> stringValue();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> numberValue();
            };
        }

        private Map<String, Object> objectValue() throws IOException {
            expect('{');
            Map<String, Object> result = new LinkedHashMap<>();
            whitespace();
            if (consume('}')) return result;
            while (true) {
                whitespace();
                if (offset >= text.length() || text.charAt(offset) != '"') fail("object key expected");
                String key = stringValue();
                whitespace();
                expect(':');
                if (result.put(key, value()) != null) fail("duplicate object key: " + key);
                whitespace();
                if (consume('}')) return result;
                expect(',');
            }
        }

        private List<Object> arrayValue() throws IOException {
            expect('[');
            List<Object> result = new ArrayList<>();
            whitespace();
            if (consume(']')) return result;
            while (true) {
                result.add(value());
                whitespace();
                if (consume(']')) return result;
                expect(',');
            }
        }

        private String stringValue() throws IOException {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (offset < text.length()) {
                char c = text.charAt(offset++);
                if (c == '"') return result.toString();
                if (c < 0x20) fail("control character in string");
                if (c != '\\') {
                    result.append(c);
                    continue;
                }
                if (offset >= text.length()) fail("unterminated escape");
                char escaped = text.charAt(offset++);
                switch (escaped) {
                    case '"', '\\', '/' -> result.append(escaped);
                    case 'b' -> result.append('\b');
                    case 'f' -> result.append('\f');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    case 'u' -> result.append((char) Integer.parseInt(hex(4), 16));
                    default -> fail("invalid escape");
                }
            }
            fail("unterminated string");
            return null;
        }

        private String hex(int length) throws IOException {
            if (offset + length > text.length()) fail("short unicode escape");
            String result = text.substring(offset, offset + length);
            for (int i = 0; i < result.length(); i++) {
                if (Character.digit(result.charAt(i), 16) < 0) fail("invalid unicode escape");
            }
            offset += length;
            return result;
        }

        private Object numberValue() throws IOException {
            int start = offset;
            if (consume('-') && offset >= text.length()) fail("invalid number");
            digits();
            if (consume('.')) {
                if (!hasDigit()) fail("invalid number fraction");
                digits();
            }
            if (offset < text.length() && (text.charAt(offset) == 'e' || text.charAt(offset) == 'E')) {
                offset++;
                if (offset < text.length() && (text.charAt(offset) == '+' || text.charAt(offset) == '-')) offset++;
                if (!hasDigit()) fail("invalid number exponent");
                digits();
            }
            try {
                return new BigDecimal(text.substring(start, offset));
            } catch (NumberFormatException failure) {
                fail("invalid number");
                return null;
            }
        }

        private void digits() throws IOException {
            if (!hasDigit()) fail("digit expected");
            while (hasDigit()) offset++;
        }

        private boolean hasDigit() {
            return offset < text.length() && text.charAt(offset) >= '0' && text.charAt(offset) <= '9';
        }

        private Object literal(String expected, Object value) throws IOException {
            if (!text.startsWith(expected, offset)) fail("invalid literal");
            offset += expected.length();
            return value;
        }

        private void whitespace() {
            while (offset < text.length() && Character.isWhitespace(text.charAt(offset))) offset++;
        }

        private boolean consume(char expected) {
            if (offset < text.length() && text.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private void expect(char expected) throws IOException {
            if (!consume(expected)) fail("expected '" + expected + "'");
        }

        private void fail(String message) throws IOException {
            throw new IOException(source + " at character " + offset + ": " + message);
        }
    }
}
