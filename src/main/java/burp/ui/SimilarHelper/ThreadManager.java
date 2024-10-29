package burp.ui.SimilarHelper;


import burp.utils.Utils;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadManager {
    private static final int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int MAX_POOL_SIZE = CORE_POOL_SIZE * 2;
    private static final long KEEP_ALIVE_TIME = 60L;

    private static final ExecutorService executorService = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(1000),
            new ThreadFactory() {
                private final AtomicInteger counter = new AtomicInteger();
                @Override
                public Thread newThread(Runnable r) {
                    Thread thread = new Thread(r);
                    thread.setName("SimilarUI-Worker-" + counter.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()
    );

    public static void execute(Runnable task) {
        executorService.execute(() -> {
            try {
                task.run();
            } catch (Exception e) {
                Utils.stderr.println("Task execution failed: " + e.getMessage());
                e.printStackTrace(Utils.stderr);
            }
        });
    }

    public static <T> Future<T> submit(Callable<T> task) {
        return executorService.submit(() -> {
            try {
                return task.call();
            } catch (Exception e) {
                Utils.stderr.println("Task execution failed: " + e.getMessage());
                e.printStackTrace(Utils.stderr);
                throw e;
            }
        });
    }

    public static void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
