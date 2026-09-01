package burp.ui.SimilarHelper;

import org.junit.After;
import org.junit.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ThreadManagerTest {
    @After
    public void tearDown() {
        ThreadManager.shutdown();
    }

    @Test
    public void rejectsAfterShutdownAndCanRestartExplicitly() throws Exception {
        ThreadManager.start();
        CountDownLatch first = new CountDownLatch(1);
        assertTrue(ThreadManager.execute(first::countDown));
        assertTrue(first.await(2, TimeUnit.SECONDS));

        ThreadManager.shutdown();
        assertFalse(ThreadManager.execute(() -> { }));

        ThreadManager.start();
        CountDownLatch second = new CountDownLatch(1);
        assertTrue(ThreadManager.execute(second::countDown));
        assertTrue(second.await(2, TimeUnit.SECONDS));
    }

    @Test
    public void supplyAsyncCompletesValueAndRejectsAfterShutdown() throws Exception {
        ThreadManager.start();
        CompletableFuture<String> completed = ThreadManager.supplyAsync(() -> "ok");
        assertEquals("ok", completed.get(2, TimeUnit.SECONDS));

        ThreadManager.shutdown();
        CompletableFuture<String> rejected = ThreadManager.supplyAsync(() -> "late");
        try {
            rejected.get(2, TimeUnit.SECONDS);
            fail("shutdown 后 supplyAsync 应被拒绝");
        } catch (ExecutionException e) {
            assertTrue("拒绝原因应为 RejectedExecutionException，实际: " + e.getCause(),
                    e.getCause() instanceof RejectedExecutionException);
        }
    }
}
