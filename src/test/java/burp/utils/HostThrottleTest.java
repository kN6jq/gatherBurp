package burp.utils;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HostThrottleTest {

    @After
    public void tearDown() {
        HostThrottle.reset();
    }

    @Test
    public void secondCallWithinIntervalIsDelayed() {
        String host = "throttle.test:80";
        long interval = 60L;
        HostThrottle.throttle(host, interval); // 第一次：记录时间戳
        long started = System.currentTimeMillis();
        HostThrottle.throttle(host, interval); // 第二次：应等待到间隔满足
        long elapsed = System.currentTimeMillis() - started;
        assertTrue("第二次调用应至少等待约一个间隔，实际 " + elapsed + "ms", elapsed >= 40L);
    }

    @Test
    public void differentHostsAreIndependent() {
        HostThrottle.throttle("a.test:80", 500L);
        long started = System.currentTimeMillis();
        HostThrottle.throttle("b.test:80", 500L); // 不同 host 不互相影响
        long elapsed = System.currentTimeMillis() - started;
        assertTrue("不同 host 不应互相等待，实际 " + elapsed + "ms", elapsed < 100L);
    }

    @Test
    public void markSlowUpgradesIntervalToSlowFloor() {
        String host = "slow.test:80";
        long started = System.currentTimeMillis();
        HostThrottle.throttle(host, 10L);
        long firstElapsed = System.currentTimeMillis() - started;

        HostThrottle.markSlow(host);
        started = System.currentTimeMillis();
        HostThrottle.throttle(host, 10L); // 基础间隔 10ms，但慢速主机至少 300ms
        long secondElapsed = System.currentTimeMillis() - started;

        assertTrue("慢速主机第二次应等待至少 250ms 左右，实际 " + secondElapsed + "ms",
                secondElapsed >= 250L);
        assertTrue(HostThrottle.isSlow(host));
        assertTrue("普通间隔调用耗时应远小于慢速间隔，实际 " + firstElapsed + "ms", firstElapsed < 250L);
    }

    @Test
    public void slowMarkExpiresAfterTtl() throws Exception {
        long originalTtl = HostThrottle.SLOW_HOST_TTL_MS;
        try {
            HostThrottle.SLOW_HOST_TTL_MS = 40L;
            String host = "ttl.test:80";
            HostThrottle.markSlow(host);
            assertTrue(HostThrottle.isSlow(host));
            Thread.sleep(60L);
            assertFalse("慢速标记应在 TTL 过期后自动失效", HostThrottle.isSlow(host));
        } finally {
            HostThrottle.SLOW_HOST_TTL_MS = originalTtl;
        }
    }

    @Test
    public void resetClearsSlowMarks() {
        String host = "reset.test:80";
        HostThrottle.markSlow(host);
        assertTrue(HostThrottle.isSlow(host));
        HostThrottle.reset();
        assertFalse(HostThrottle.isSlow(host));
    }
}
