package fabricpacker;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal, abhaengigkeitsfreier Test-Runner.
 * Ausfuehrung: java -cp testbuild fabricpacker.TestRunner
 */
public final class TestRunner {
    private static final List<Class<?>> SUITES = List.of(
            SimpleJsonTests.class,
            SignatureSupportTests.class,
            FabricPackerCliTests.class,
            PackedClassLoaderHelperTests.class);

    private static int passed;
    private static final List<String> failures = new ArrayList<>();

    private TestRunner() {
    }

    public static void main(String[] args) {
        for (Class<?> suite : SUITES) {
            for (Method method : suite.getDeclaredMethods()) {
                if (!method.getName().startsWith("test") || method.getParameterCount() != 0) continue;
                if (!java.lang.reflect.Modifier.isStatic(method.getModifiers())) continue;
                run(suite, method);
            }
        }
        System.out.println();
        System.out.println("Tests: " + (passed + failures.size()) + ", passed: " + passed
                + ", failed: " + failures.size());
        if (!failures.isEmpty()) {
            for (String failure : failures) System.out.println("FAILED: " + failure);
            System.exit(1);
        }
    }

    private static void run(Class<?> suite, Method method) {
        String name = suite.getSimpleName() + "." + method.getName();
        try {
            method.setAccessible(true);
            method.invoke(null);
            passed++;
            System.out.println("PASS " + name);
        } catch (Throwable failure) {
            Throwable cause = failure;
            while (cause.getCause() != null) cause = cause.getCause();
            failures.add(name + " -> " + failure + " | root: " + cause);
            System.out.println("FAIL " + name + " -> " + failure + " | root: " + cause);
        }
    }

    static void assertTrue(boolean condition) {
        if (!condition) throw new AssertionError("expected true");
    }

    static void assertFalse(boolean condition) {
        if (condition) throw new AssertionError("expected false");
    }

    static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("expected " + expected + " but was " + actual);
        }
    }

    static void assertThrows(Class<? extends Throwable> type, Action action) {
        try {
            action.run();
        } catch (Throwable failure) {
            Throwable actual = failure;
            while (actual instanceof java.lang.reflect.InvocationTargetException) {
                Throwable cause = actual.getCause();
                if (cause == null) break;
                actual = cause;
            }
            if (type.isInstance(actual)) return;
            throw new AssertionError("expected " + type.getSimpleName() + " but was " + actual, actual);
        }
        throw new AssertionError("expected " + type.getSimpleName() + " but nothing was thrown");
    }

    interface Action {
        void run() throws Throwable;
    }
}