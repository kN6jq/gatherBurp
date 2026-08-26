package burp.utils;

import org.junit.After;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScanTaskExecutorTest {
    @After
    public void tearDown() {
        ScanTaskExecutor.shutdown();
    }

    @Test
    public void supportsExplicitRestartAfterExtensionReload() throws Exception {
        ScanTaskExecutor.start();
        CountDownLatch first = new CountDownLatch(1);
        assertTrue(ScanTaskExecutor.execute("first", first::countDown));
        assertTrue(first.await(2, TimeUnit.SECONDS));

        ScanTaskExecutor.shutdown();
        assertFalse(ScanTaskExecutor.execute("stopped", () -> { }));

        ScanTaskExecutor.start();
        CountDownLatch second = new CountDownLatch(1);
        assertTrue(ScanTaskExecutor.execute("second", second::countDown));
        assertTrue(second.await(2, TimeUnit.SECONDS));
    }
}
