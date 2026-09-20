package fabricpacker;

import java.lang.reflect.Method;

final class PackedClassLoaderHelperTests {
    private PackedClassLoaderHelperTests() {
    }

    private static Object call(String name, Object... args) throws Exception {
        Method method = PackedClassLoader.class.getDeclaredMethod(name, String.class);
        method.setAccessible(true);
        return method.invoke(null, args);
    }

    static void testValidEntryPath() throws Exception {
        TestRunner.assertEquals(Boolean.TRUE, call("validEntryPath", "com/example/Foo.class"));
        TestRunner.assertEquals(Boolean.TRUE, call("validEntryPath", "assets/lang/en_us.json"));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", (Object) null));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", ""));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", "/absolute"));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", "back\\slash"));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", ".."));
        TestRunner.assertEquals(Boolean.FALSE, call("validEntryPath", "com/../evil"));
    }

    static void testNormalizeResourceName() throws Exception {
        TestRunner.assertEquals("", call("normalizeResourceName", (Object) null));
        TestRunner.assertEquals("x", call("normalizeResourceName", "/x"));
        TestRunner.assertEquals("x", call("normalizeResourceName", "x"));
    }
}