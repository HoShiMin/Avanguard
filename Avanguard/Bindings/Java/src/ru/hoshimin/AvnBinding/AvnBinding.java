package ru.hoshimin.AvnBinding;

public class AvnBinding {

    enum ThreatType {
        REMOTE_THREAD(0),
        THREAD_IN_UNKNOWN_MODULE(1),
        THREAD_IN_UNKNOWN_MEMORY(2),
        UNKNOWN_ORIGIN_MODLOAD(3),
        WINDOWS_HOOKS(4),
        APP_INIT_DLLS(5),
        APC(6),
        CONTEXT_STEAL(7),
        MODIFIED_MODULE(8),
        UNKNOWN_MEMORY(9),
        UNKNOWN(10);

        private final int id;

        ThreatType(int id) {
            this.id = id;
        }

        public int getValue() { return id; }
    }

    enum ThreatDecision {
        ALLOW(0),
        TERMINATE(1),
        BLOCK_OR_IGNORE(2),
        BLOCK_OR_TERMINATE(3);

        private final int id;

        ThreatDecision(int id) {
            this.id = id;
        }

        public int getValue() { return id; }
    }

    public abstract class ThreatInfo {
        ThreatType type;
        public ThreatType getType() { return type; }
    }

    public class RemoteThreadInfo extends ThreatInfo {
        private final long entryPoint;
        private final long argument;
        RemoteThreadInfo(long entryPoint, long argument) {
            type = ThreatType.REMOTE_THREAD;
            this.entryPoint = entryPoint;
            this.argument = argument;
        }
        public long getEntryPoint() { return entryPoint; }
        public long getArgument() { return argument; }
    }

    public class ThreadInUnknownModuleInfo extends ThreatInfo {
        private final long entryPoint;
        private final long argument;
        ThreadInUnknownModuleInfo(long entryPoint, long argument) {
            type = ThreatType.THREAD_IN_UNKNOWN_MODULE;
            this.entryPoint = entryPoint;
            this.argument = argument;
        }
        public long getEntryPoint() { return entryPoint; }
        public long getArgument() { return argument; }
    }

    public class ThreadInUnknownMemoryInfo extends ThreatInfo {
        private final long entryPoint;
        private final long argument;
        ThreadInUnknownMemoryInfo(long entryPoint, long argument) {
            type = ThreatType.THREAD_IN_UNKNOWN_MEMORY;
            this.entryPoint = entryPoint;
            this.argument = argument;
        }
        public long getEntryPoint() { return entryPoint; }
        public long getArgument() { return argument; }
    }

    public class UnknownOriginModloadInfo extends ThreatInfo {
        private final long unknownFrame;
        private final String path;
        UnknownOriginModloadInfo(long unknownFrame, String path) {
            type = ThreatType.UNKNOWN_ORIGIN_MODLOAD;
            this.unknownFrame = unknownFrame;
            this.path = path;
        }
        public long getUnknownFrame() { return unknownFrame; }
        public String getPath() { return path; }
    }

    public class WindowsHooksInfo extends ThreatInfo {
        private final String path;
        WindowsHooksInfo(String path) {
            type = ThreatType.WINDOWS_HOOKS;
            this.path = path;
        }
        public String getPath() { return path; }
    }

    public class AppInitDllsInfo extends ThreatInfo {
        private final String path;
        AppInitDllsInfo(String path) {
            type = ThreatType.APP_INIT_DLLS;
            this.path = path;
        }
        public String getPath() { return path; }
    }

    public class ApcInfo extends ThreatInfo {
        private final long apcRoutine;
        private final long argument;
        ApcInfo(long apcRoutine, long argument) {
            type = ThreatType.APC;
            this.apcRoutine = apcRoutine;
            this.argument = argument;
        }
        public long getApcRoutine() { return apcRoutine; }
        public long getArgument() { return argument; }
    }

    public class ContextStealInfo extends ThreatInfo {
        private final long unknownMemory;
        ContextStealInfo(long unknownMemory) {
            type = ThreatType.CONTEXT_STEAL;
            this.unknownMemory = unknownMemory;
        }
        public long getUnknownMemory() { return unknownMemory; }
    }

    public class ModifiedModuleInfo extends ThreatInfo {
        private final long moduleBase;
        private final String name;
        ModifiedModuleInfo(long moduleBase, String name) {
            type = ThreatType.MODIFIED_MODULE;
            this.moduleBase = moduleBase;
            this.name = name;
        }
        public long getModuleBase() { return moduleBase; }
        public String getName() { return name; }
    }

    public class UnknownMemoryInfo extends ThreatInfo {
        private final long allocationBase;
        private final long size;
        UnknownMemoryInfo(long allocationBase, long size) {
            type = ThreatType.UNKNOWN_MEMORY;
            this.allocationBase = allocationBase;
            this.size = size;
        }
        public long getAllocationBase() { return allocationBase; }
        public long getSize() { return size; }
    }

    public interface ThreatNotifier {
        ThreatDecision call(ThreatInfo threatInfo);
    }

    static {
        System.load("F:/Programming/ProgramsAvanguard.dll");
    }

    public static native boolean isStarted();
    public static native boolean isStaticLoaded();
    public static native void subscribe(ThreatNotifier callback);
}
