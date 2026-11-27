package burp.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 按模块隔离的扫描任务池：每个模块单独创建线程池，模块之间不共享执行线程或队列。
 * 每池两个线程、256 个排队任务；队列满或关闭时拒绝新任务并打 stderr。
 */
public final class ScanTaskExecutor {
    private static final int MODULE_POOL_SIZE = 2;
    private static final int QUEUE_CAPACITY = 256;

    private static final Object LIFECYCLE_LOCK = new Object();
    private static final Map<String, ThreadPoolExecutor> EXECUTORS = new ConcurrentHashMap<>();
    private static volatile boolean acceptingTasks = true;

    private ScanTaskExecutor() {
    }

    /** 提交任务到指定模块的独立池；池已关闭或队列满返回 false。 */
    public static boolean execute(String moduleName, String taskName, Runnable task) {
        if (task == null || moduleName == null || moduleName.trim().isEmpty()) {
            logError("task rejected: module name is empty", null);
            return false;
        }
        String poolKey = moduleName.toLowerCase(Locale.ROOT);
        ThreadPoolExecutor current = executorForSubmit(poolKey);
        if (current == null) {
            return false;
        }
        try {
            current.execute(() -> {
                try {
                    task.run();
                } catch (Throwable throwable) {
                    logError(taskName + " failed: " + throwable.getMessage(), throwable);
                }
            });
            return true;
        } catch (RejectedExecutionException ex) {
            logError(moduleName + " rejected: module queue is full or shutting down", null);
            return false;
        }
    }

    private static ThreadPoolExecutor executorForSubmit(String moduleName) {
        synchronized (LIFECYCLE_LOCK) {
            if (!acceptingTasks) {
                return null;
            }
            ThreadPoolExecutor current = EXECUTORS.get(moduleName);
            if (current == null || current.isShutdown()) {
                current = createExecutor(moduleName);
                EXECUTORS.put(moduleName, current);
            }
            return current;
        }
    }

    /** 恢复任务接收；各模块池在首次提交任务时按需创建。 */
    public static void start() {
        synchronized (LIFECYCLE_LOCK) {
            acceptingTasks = true;
        }
    }

    /** 停止接收新任务，关闭所有模块池并等待在途任务退出。 */
    public static void shutdown() {
        List<ThreadPoolExecutor> currentExecutors;
        synchronized (LIFECYCLE_LOCK) {
            acceptingTasks = false;
            currentExecutors = new ArrayList<>(EXECUTORS.values());
            EXECUTORS.clear();
        }
        for (ThreadPoolExecutor executor : currentExecutors) {
            executor.shutdownNow();
        }
        for (ThreadPoolExecutor executor : currentExecutors) {
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    logError("scan pool did not terminate within 5 seconds", null);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logError("interrupted while waiting for scan pools to stop", e);
                break;
            }
        }
    }

    /** 返回指定模块的队列积压数（测试/监控用）。 */
    static int getQueueSize(String moduleName) {
        ThreadPoolExecutor current = EXECUTORS.get(moduleName.toLowerCase(Locale.ROOT));
        return current == null ? 0 : current.getQueue().size();
    }

    private static ThreadPoolExecutor createExecutor(String moduleName) {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                MODULE_POOL_SIZE,
                MODULE_POOL_SIZE,
                30L,
                TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(QUEUE_CAPACITY),
                new ScanThreadFactory(moduleName),
                new ThreadPoolExecutor.AbortPolicy()
        );
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    private static void logError(String message, Throwable throwable) {
        if (Utils.stderr != null) {
            Utils.stderr.println(message);
            if (throwable != null) {
                throwable.printStackTrace(Utils.stderr);
            }
        } else {
            System.err.println(message);
            if (throwable != null) {
                throwable.printStackTrace(System.err);
            }
        }
    }

    private static final class ScanThreadFactory implements ThreadFactory {
        private final String moduleName;
        private final AtomicInteger sequence = new AtomicInteger();

        private ScanThreadFactory(String moduleName) {
            this.moduleName = moduleName;
        }

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable,
                    "GatherBurp-" + moduleName + "-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
