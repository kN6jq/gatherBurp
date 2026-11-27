package burp.utils;

import java.util.concurrent.atomic.AtomicLong;

/** 被动扫描取消标记：关闭开关使当前任务和同代次的排队任务失效。 */
public final class PassiveScanCancellation {
    private final AtomicLong generation = new AtomicLong();
    private static final ThreadLocal<Token> CURRENT_TOKEN = new ThreadLocal<>();

    public long captureGeneration() {
        return generation.get();
    }

    public void cancel() {
        generation.incrementAndGet();
    }

    public boolean isGenerationStale(long taskGeneration) {
        return taskGeneration != generation.get();
    }

    public static void run(PassiveScanCancellation owner, long generation, Runnable task) {
        CURRENT_TOKEN.set(new Token(owner, generation));
        try {
            task.run();
        } finally {
            CURRENT_TOKEN.remove();
        }
    }

    public static boolean isCancelled() {
        Token token = CURRENT_TOKEN.get();
        return token != null && token.generation != token.owner.generation.get();
    }

    private static final class Token {
        private final PassiveScanCancellation owner;
        private final long generation;

        private Token(PassiveScanCancellation owner, long generation) {
            this.owner = owner;
            this.generation = generation;
        }
    }
}
