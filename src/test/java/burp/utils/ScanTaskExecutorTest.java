package burp.utils;

import org.junit.After;
import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
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
        assertTrue(ScanTaskExecutor.execute("Auth", "first", first::countDown));
        assertTrue(first.await(2, TimeUnit.SECONDS));

        ScanTaskExecutor.shutdown();
        assertFalse(ScanTaskExecutor.execute("Auth", "stopped", () -> { }));

        ScanTaskExecutor.start();
        CountDownLatch auth = new CountDownLatch(1);
        CountDownLatch sql = new CountDownLatch(1);
        assertTrue(ScanTaskExecutor.execute("Auth", "auth", auth::countDown));
        assertTrue(ScanTaskExecutor.execute("SQL", "sql", sql::countDown));
        assertTrue(auth.await(2, TimeUnit.SECONDS));
        assertTrue(sql.await(2, TimeUnit.SECONDS));
    }

    @Test
    public void fullModuleQueueDoesNotBlockOtherModules() throws Exception {
        ScanTaskExecutor.start();
        CountDownLatch routeWorkersStarted = new CountDownLatch(2);
        CountDownLatch releaseRouteWorkers = new CountDownLatch(1);
        try {
            for (int i = 0; i < 2; i++) {
                assertTrue(ScanTaskExecutor.execute("Route", "blocking route", () -> {
                    routeWorkersStarted.countDown();
                    try {
                        releaseRouteWorkers.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }));
            }
            assertTrue(routeWorkersStarted.await(2, TimeUnit.SECONDS));

            while (ScanTaskExecutor.getQueueSize("Route") < 256) {
                assertTrue(ScanTaskExecutor.execute("Route", "queued route", () -> { }));
            }
            assertEquals(256, ScanTaskExecutor.getQueueSize("route"));
            assertFalse(ScanTaskExecutor.execute("Route", "overflow route", () -> { }));

            CountDownLatch sqlRan = new CountDownLatch(1);
            assertTrue(ScanTaskExecutor.execute("SQL", "sql", sqlRan::countDown));
            assertTrue(sqlRan.await(2, TimeUnit.SECONDS));
        } finally {
            releaseRouteWorkers.countDown();
        }
    }

    @Test
    public void rejectsEmptyModuleName() {
        ScanTaskExecutor.start();
        assertFalse(ScanTaskExecutor.execute("", "invalid", () -> { }));
        assertFalse(ScanTaskExecutor.execute(null, "invalid", () -> { }));
    }

    @Test
    public void overlappingLifecycleCallsKeepRegistryUsable() throws Exception {
        for (int i = 0; i < 50; i++) {
            ScanTaskExecutor.start();
            CountDownLatch begin = new CountDownLatch(1);
            Thread stopper = new Thread(() -> {
                try {
                    begin.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                ScanTaskExecutor.shutdown();
            });
            Thread starter = new Thread(() -> {
                try {
                    begin.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                ScanTaskExecutor.start();
            });
            stopper.setDaemon(true);
            starter.setDaemon(true);
            stopper.start();
            starter.start();
            begin.countDown();
            stopper.join();
            starter.join();

            ScanTaskExecutor.start();
            CountDownLatch ran = new CountDownLatch(1);
            assertTrue(ScanTaskExecutor.execute("SQL", "probe", ran::countDown));
            assertTrue(ran.await(2, TimeUnit.SECONDS));
        }
    }

    @Test
    public void shutdownInterruptsAndWaitsForCooperativeTask() throws Exception {
        ScanTaskExecutor.start();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch stopped = new CountDownLatch(1);
        assertTrue(ScanTaskExecutor.execute("Auth", "blocking", () -> {
            started.countDown();
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException e) {
                stopped.countDown();
            }
        }));
        assertTrue(started.await(2, TimeUnit.SECONDS));

        ScanTaskExecutor.shutdown();

        assertEquals(0, stopped.getCount());
    }
}
