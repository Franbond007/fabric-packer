package fabricpacker;

import java.lang.reflect.Method;
import java.util.List;

final class FabricPackerCliTests {
    private FabricPackerCliTests() {
    }

    private static Object call(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = FabricPacker.class.getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    static void testParseOptionsMinimal() throws Exception {
        FabricPacker.Options options = (FabricPacker.Options) call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"in.jar"});
        TestRunner.assertEquals("in.jar", options.input().getFileName().toString());
        TestRunner.assertTrue(options.output() == null);
        TestRunner.assertFalse(options.help());
        TestRunner.assertTrue(options.excludes().isEmpty());
        TestRunner.assertFalse(options.quiet());
    }

    static void testParseOptionsFull() throws Exception {
        String[] args = {"in.jar", "cfg.json", "--output", "out.jar", "--exclude", "com.example.Foo",
                "--exclude", "assets/x.txt", "--watermark", "kunde-1", "--quiet", "--verbose",
                "--compression", "5", "--parallel", "3"};
        FabricPacker.Options options = (FabricPacker.Options) call("parseOptions",
                new Class<?>[]{String[].class}, (Object) args);
        TestRunner.assertEquals("out.jar", options.output().getFileName().toString());
        TestRunner.assertEquals("cfg.json", options.config().getFileName().toString());
        TestRunner.assertEquals(List.of("com.example.Foo", "assets/x.txt"), options.excludes());
        TestRunner.assertEquals("kunde-1", options.watermark());
        TestRunner.assertEquals(Integer.valueOf(5), options.compression());
        TestRunner.assertEquals(Integer.valueOf(3), options.parallelism());
        TestRunner.assertTrue(options.quiet());
        TestRunner.assertTrue(options.verbose());
    }

    static void testParseOptionsHelp() throws Exception {
        FabricPacker.Options options = (FabricPacker.Options) call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"--help"});
        TestRunner.assertTrue(options.help());
    }

    static void testParseOptionsRejectsUnknownOption() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"--bogus"}));
    }

    static void testParseOptionsRejectsMissingValue() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"--output"}));
    }

    static void testParseOptionsRejectsBadCompression() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"--compression", "10", "in.jar"}));
    }

    static void testParseOptionsRejectsBadParallel() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"--parallel", "0", "in.jar"}));
    }

    static void testParseOptionsRejectsExtraPositional() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[]{"a.jar", "b.jar", "c.jar"}));
    }

    static void testParseOptionsRejectsMissingInput() {
        TestRunner.assertThrows(IllegalArgumentException.class, () -> call("parseOptions",
                new Class<?>[]{String[].class}, (Object) new String[0]));
    }

    static void testReadConfigDefaults() throws Exception {
        FabricPacker.PackConfig config = (FabricPacker.PackConfig) call("readConfig",
                new Class<?>[]{String.class}, "{}");
        TestRunner.assertTrue(config.excludes().isEmpty());
        TestRunner.assertTrue(config.leakTerms().isEmpty());
        TestRunner.assertEquals(Integer.valueOf(9), Integer.valueOf(config.compression()));
        TestRunner.assertTrue(config.parallelism() >= 1);
    }

    static void testReadConfigExcludes() throws Exception {
        FabricPacker.PackConfig config = (FabricPacker.PackConfig) call("readConfig",
                new Class<?>[]{String.class},
                "{\"class\":[\"com.example.Foo\"],\"resources\":[\"assets/x.txt\"]}");
        TestRunner.assertTrue(config.excludes().contains("com/example/Foo"));
        TestRunner.assertTrue(config.excludes().contains("assets/x.txt"));
    }

    static void testReadConfigNumbers() throws Exception {
        FabricPacker.PackConfig config = (FabricPacker.PackConfig) call("readConfig",
                new Class<?>[]{String.class}, "{\"compression\":5,\"parallelism\":2}");
        TestRunner.assertEquals(Integer.valueOf(5), Integer.valueOf(config.compression()));
        TestRunner.assertEquals(Integer.valueOf(2), Integer.valueOf(config.parallelism()));
    }

    static void testReadConfigLeakTerms() throws Exception {
        FabricPacker.PackConfig config = (FabricPacker.PackConfig) call("readConfig",
                new Class<?>[]{String.class}, "{\"leakTerms\":[\"MyFeature\",\"Second\"]}");
        TestRunner.assertEquals(List.of("MyFeature", "Second"), config.leakTerms());
    }

    static void testReadConfigUnknownKeyIgnored() throws Exception {
        FabricPacker.PackConfig config = (FabricPacker.PackConfig) call("readConfig",
                new Class<?>[]{String.class}, "{\"typo\":1}");
        TestRunner.assertTrue(config.excludes().isEmpty());
    }

    static void testReadConfigRejectsBadCompression() {
        TestRunner.assertThrows(java.io.IOException.class, () -> call("readConfig",
                new Class<?>[]{String.class}, "{\"compression\":10}"));
    }

    static void testReadConfigRejectsBadParallelism() {
        TestRunner.assertThrows(java.io.IOException.class, () -> call("readConfig",
                new Class<?>[]{String.class}, "{\"parallelism\":0}"));
    }

    static void testReadConfigRejectsNonIntegerCompression() {
        TestRunner.assertThrows(java.io.IOException.class, () -> call("readConfig",
                new Class<?>[]{String.class}, "{\"compression\":5.5}"));
    }

    static void testReadConfigRejectsBadLeakTermsType() {
        TestRunner.assertThrows(java.io.IOException.class, () -> call("readConfig",
                new Class<?>[]{String.class}, "{\"leakTerms\":\"x\"}"));
    }

    static void testReadConfigRejectsBlankLeakTerm() {
        TestRunner.assertThrows(java.io.IOException.class, () -> call("readConfig",
                new Class<?>[]{String.class}, "{\"leakTerms\":[\"ok\",\"\"]}"));
    }

    static void testBuildWatermarkDeterministic() throws Exception {
        byte[] first = (byte[]) call("buildWatermark", new Class<?>[]{String.class}, "kunde-1");
        byte[] second = (byte[]) call("buildWatermark", new Class<?>[]{String.class}, "kunde-1");
        byte[] other = (byte[]) call("buildWatermark", new Class<?>[]{String.class}, "kunde-2");
        byte[] random = (byte[]) call("buildWatermark", new Class<?>[]{String.class}, (Object) null);
        TestRunner.assertTrue(java.util.Arrays.equals(first, second));
        TestRunner.assertFalse(java.util.Arrays.equals(first, other));
        TestRunner.assertEquals(24, first.length);
        TestRunner.assertEquals(24, random.length);
    }
}