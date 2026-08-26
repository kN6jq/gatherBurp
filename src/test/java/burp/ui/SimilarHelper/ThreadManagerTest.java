package burp.ui.SimilarHelper;

import org.junit.After;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
}
