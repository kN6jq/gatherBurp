package burp.utils;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描任务共享线程池：防止 Burp 监听器/菜单动作创建无限线程。
 * 有界队列 + AbortPolicy，拒绝时打 stderr。shutdown 后可 start 恢复。
 */
public final class ScanTaskExecutor {
    private static final int CPU_COUNT = Math.max(2, Runtime.getRuntime().availableProcessors());
    private static final int POOL_SIZE = Math.min(8, CPU_COUNT);
    private static final int QUEUE_CAPACITY = 256;

    private static final Object LIFECYCLE_LOCK = new Object();
    private static volatile ThreadPoolExecutor executor = createExecutor();
    private static volatile boolean acceptingTasks = true;

    private static ThreadPoolExecutor createExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            POOL_SIZE,
            POOL_SIZE,
            30L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(QUEUE_CAPACITY),
            new ScanThreadFactory(),
            new ThreadPoolExecutor.AbortPolicy()
        );
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    private ScanTaskExecutor() {
    }

    /** 提交任务到池（自动包裹异常捕获）。池已关闭或队列满返回 false。 */
    public static boolean execute(String taskName, Runnable task) {
        if (task == null) {
            return false;
        }
        ThreadPoolExecutor current = executorForSubmit();
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
            logError(taskName + " rejected: scan queue is full or shutting down", null);
            return false;
        }
    }

    /** 获取可用池实例：已关闭则重建，不接收任务时返回 null。 */
    private static ThreadPoolExecutor executorForSubmit() {
        synchronized (LIFECYCLE_LOCK) {
            if (!acceptingTasks) {
                return null;
            }
            ThreadPoolExecutor current = executor;
            if (current == null || current.isShutdown()) {
                current = createExecutor();
                executor = current;
            }
            return current;
        }
    }

    /** 启动/恢复任务接收。 */
    public static void start() {
        synchronized (LIFECYCLE_LOCK) {
            acceptingTasks = true;
            executor();
        }
    }

    /** 关闭池：停止接收新任务并 shutdownNow 已排队线程。 */
    public static void shutdown() {
        acceptingTasks = false;
        ThreadPoolExecutor current;
        synchronized (LIFECYCLE_LOCK) {
            current = executor;
            executor = null;
        }
        if (current != null) {
            current.shutdownNow();
        }
    }

    /** 返回当前队列积压数（测试/监控用）。 */
    static int getQueueSize() {
        ThreadPoolExecutor current = executor;
        return current == null ? 0 : current.getQueue().size();
    }

    /** 获取当前池实例：已关闭则重建。 */
    private static ThreadPoolExecutor executor() {
        ThreadPoolExecutor current = executor;
        if (current != null && !current.isShutdown()) {
            return current;
        }
        synchronized (LIFECYCLE_LOCK) {
            current = executor;
            if (current == null || current.isShutdown()) {
                current = createExecutor();
                executor = current;
            }
            return current;
        }
    }

    /** 错误日志：优先写 Burp stderr，未注入时写 System.err。 */
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
        private final AtomicInteger sequence = new AtomicInteger();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "GatherBurp-Scan-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
