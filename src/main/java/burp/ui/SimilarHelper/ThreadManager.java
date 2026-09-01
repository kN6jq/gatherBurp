package burp.ui.SimilarHelper;

import burp.utils.Utils;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/** Similar 模块的有界后台执行器，支持扩展热重载后按需重建。 */
public final class ThreadManager {
    private static final int CORE_POOL_SIZE = Math.min(8,
            Math.max(2, Runtime.getRuntime().availableProcessors()));
    private static final int MAX_POOL_SIZE = Math.min(16, CORE_POOL_SIZE * 2);
    private static final long KEEP_ALIVE_TIME = 60L;
    private static final int QUEUE_CAPACITY = 1000;
    private static final Object LIFECYCLE_LOCK = new Object();

    private static volatile ThreadPoolExecutor executorService = createExecutor();
    private static volatile boolean acceptingTasks = true;

    private ThreadManager() {
    }

    /**
     * 提交后台任务。队列满时直接拒绝而不是让 Burp listener/EDT 执行耗时任务。
     */
    public static boolean execute(Runnable task) {
        if (task == null) {
            return false;
        }
        // 生命周期检查与取池在同一把锁内完成：
        // 避免 shutdown 刚置空 executorService 时，已通过的 acceptingTasks 检查仍触发 executor() 重建出"无人持有"的池
        ThreadPoolExecutor target;
        synchronized (LIFECYCLE_LOCK) {
            if (!acceptingTasks) {
                return false;
            }
            target = executor();
        }
        try {
            target.execute(wrap(task));
            return true;
        } catch (RejectedExecutionException e) {
            logError("Similar task rejected: queue is full or executor is shutting down", null);
            return false;
        }
    }

    /** 提交返回结果的任务：关闭期或队列满抛 RejectedExecutionException；任务异常原样透传给 Future。 */
    public static <T> Future<T> submit(Callable<T> task) {
        if (!acceptingTasks) {
            throw new RejectedExecutionException("Similar executor is shutting down");
        }
        if (task == null) {
            throw new IllegalArgumentException("task must not be null");
        }
        try {
            return executor().submit(() -> {
                try {
                    return task.call();
                } catch (Throwable throwable) {
                    logError("Similar task execution failed: " + throwable.getMessage(), throwable);
                    if (throwable instanceof Exception) {
                        throw (Exception) throwable;
                    }
                    throw new RuntimeException(throwable);
                }
            });
        } catch (RejectedExecutionException e) {
            logError("Similar task rejected: queue is full or executor is shutting down", null);
            throw e;
        }
    }

    /**
     * 在有界线程池上执行异步供给任务，供 CompletableFuture 组合使用。
     * 替代 CompletableFuture.supplyAsync 的默认 ForkJoinPool.commonPool——后者无界，
     * 大流量下任务无限堆积，违背本类的有界设计。
     */
    public static <T> CompletableFuture<T> supplyAsync(Supplier<T> task) {
        CompletableFuture<T> future = new CompletableFuture<>();
        boolean accepted = execute(() -> {
            try {
                future.complete(task.get());
            } catch (Throwable throwable) {
                future.completeExceptionally(throwable);
            }
        });
        if (!accepted) {
            future.completeExceptionally(new RejectedExecutionException("Similar executor unavailable"));
        }
        return future;
    }

    /** 在扩展重新加载时重新开放任务提交。 */
    public static void start() {
        synchronized (LIFECYCLE_LOCK) {
            acceptingTasks = true;
            executor();
        }
    }

    /** 关闭执行器：先拒新任务，再等待最多 5s 排空，超时强制 shutdownNow。 */
    public static void shutdown() {
        acceptingTasks = false;
        ThreadPoolExecutor executor;
        synchronized (LIFECYCLE_LOCK) {
            executor = executorService;
            executorService = null;
        }
        if (executor == null) {
            return;
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /** 当前排队任务数（包级可见，供单测断言池状态）。 */
    static int getQueueSize() {
        ThreadPoolExecutor executor = executorService;
        return executor == null ? 0 : executor.getQueue().size();
    }

    private static ThreadPoolExecutor executor() {
        ThreadPoolExecutor executor = executorService;
        if (executor != null && !executor.isShutdown()) {
            return executor;
        }
        synchronized (LIFECYCLE_LOCK) {
            executor = executorService;
            if (executor == null || executor.isShutdown()) {
                executor = createExecutor();
                executorService = executor;
            }
            return executor;
        }
    }

    private static ThreadPoolExecutor createExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                CORE_POOL_SIZE,
                MAX_POOL_SIZE,
                KEEP_ALIVE_TIME,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                new SimilarThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy()
        );
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    private static Runnable wrap(Runnable task) {
        return () -> {
            try {
                task.run();
            } catch (Throwable throwable) {
                logError("Similar task execution failed: " + throwable.getMessage(), throwable);
            }
        };
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

    private static final class SimilarThreadFactory implements ThreadFactory {
        private final AtomicInteger counter = new AtomicInteger();

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "SimilarUI-Worker-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
