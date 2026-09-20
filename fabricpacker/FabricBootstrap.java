package fabricpacker;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.lang.management.ManagementFactory;
import java.util.List;
import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;

/** Fabric preLaunch hook that installs the packed class source before mod entrypoints run. */
public final class FabricBootstrap implements PreLaunchEntrypoint {
    @Override
    public void onPreLaunch() {
        try {
            Guard.check();
            ClassLoader bootstrapLoader = FabricBootstrap.class.getClassLoader();
            ClassLoader target = findFabricTarget(bootstrapLoader);
            ClassLoader parent = target == null ? bootstrapLoader : target;
            PackedClassLoader packed = new PackedClassLoader(parent, bootstrapLoader);
            // Fabric, Mixin and libraries such as Reflections resolve some
            // classes/resources through the thread context loader. Keep the
            // in-memory source visible for that lookup path as well as through
            // Knot's URL loader.
            Thread.currentThread().setContextClassLoader(packed);
            Runtime.getRuntime().addShutdownHook(new Thread(packed::close, "fabric-packer-cleanup"));
            Guard.watch();

            if (target != null) {
                try {
                    addToKnot(target, packed.rootUrl());
                } catch (ReflectiveOperationException | SecurityException ignored) {
                    // The context loader remains the supported in-memory fallback.
                    // A normal Fabric start must not require addUrlFwd or instrumentation.
                }
            }
        } catch (Throwable failure) {
            throw new RuntimeException(A0.e(25), failure);
        }
    }

    private static ClassLoader findFabricTarget(ClassLoader bootstrapLoader) throws Exception {
        Class<?> launcherBase;
        try {
            launcherBase = Class.forName("net.fabricmc.loader.impl.launch.FabricLauncherBase",
                    false, bootstrapLoader);
        } catch (ClassNotFoundException unavailable) {
            return null;
        }
        Method getLauncher = launcherBase.getMethod("getLauncher");
        if (!Modifier.isStatic(getLauncher.getModifiers())) throw new NoSuchMethodException(A0.e(26));
        Object launcher = getLauncher.invoke(null);
        if (launcher == null) throw new IllegalStateException(A0.e(27));
        Method targetMethod;
        try {
            Class<?> launcherApi = Class.forName("net.fabricmc.loader.impl.launch.FabricLauncher",
                    false, bootstrapLoader);
            targetMethod = launcherApi.getMethod("getTargetClassLoader");
        } catch (ClassNotFoundException unavailable) {
            targetMethod = launcher.getClass().getMethod("getTargetClassLoader");
        }
        Object target = targetMethod.invoke(launcher);
        if (!(target instanceof ClassLoader)) throw new IllegalStateException(A0.e(28));
        return (ClassLoader) target;
    }

    private static void addToKnot(ClassLoader target, URL root) throws Exception {
        Method addUrl;
        try {
            addUrl = target.getClass().getMethod("addUrlFwd", URL.class);
        } catch (NoSuchMethodException missing) {
            addUrl = target.getClass().getDeclaredMethod("addUrlFwd", URL.class);
        }
        if (Modifier.isStatic(addUrl.getModifiers()) || !addUrl.trySetAccessible()) {
            throw new IllegalStateException(A0.e(29));
        }
        addUrl.invoke(target, root);
    }
}
