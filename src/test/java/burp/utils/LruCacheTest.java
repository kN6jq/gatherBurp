package burp.utils;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class LruCacheTest {

    @Test
    public void evictsEldestEntriesBeyondCapacity() {
        LruCache<Integer, String> cache = new LruCache<>(2);
        cache.put(1, "a");
        cache.put(2, "b");
        cache.get(1); // 访问 1，使 2 成为最旧
        cache.put(3, "c"); // 淘汰 2
        assertNull(cache.get(2));
        assertEquals("a", cache.get(1));
        assertEquals("c", cache.get(3));
    }

    @Test
    public void computeIfAbsentStoresOnce() {
        LruCache<String, Integer> cache = new LruCache<>(4);
        Integer first = cache.computeIfAbsent("k", key -> Integer.valueOf(7));
        Integer second = cache.computeIfAbsent("k", key -> Integer.valueOf(9));
        assertSame(first, second);
        assertEquals(Integer.valueOf(7), second);
    }

    @Test
    public void removeKeysMatchesPrefixPredicate() {
        LruCache<String, String> cache = new LruCache<>(8);
        cache.put("1|a", "x");
        cache.put("1|b", "y");
        cache.put("2|a", "z");
        int removed = cache.removeKeys(key -> key.startsWith("1|"));
        assertEquals(2, removed);
        assertNull(cache.get("1|a"));
        assertEquals("z", cache.get("2|a"));
    }

    @Test
    public void staysConsistentUnderConcurrentAccess() throws Exception {
        final LruCache<Integer, Integer> cache = new LruCache<>(64);
        final int threads = 8;
        final CountDownLatch start = new CountDownLatch(1);
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int id = t;
            workers[t] = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        start.await();
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                    for (int i = 0; i < 500; i++) {
                        cache.put(id * 1000 + i, Integer.valueOf(i));
                        cache.get(i);
                        cache.computeIfAbsent(-1, key -> Integer.valueOf(0));
                    }
                }
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }
        assertTrue("并发写入后容量必须仍受上限约束", cache.size() <= 64);
    }

    @Test
    public void lruSetAddSemanticsMatchSet() {
        LruSet<String> set = new LruSet<>(2);
        assertTrue(set.add("a"));
        assertFalse("重复 add 应返回 false", set.add("a"));
        assertTrue(set.add("b"));
        assertTrue(set.add("c")); // 容量耗尽，淘汰最旧的 "a"
        assertFalse(set.contains("a"));
        assertTrue(set.contains("b"));
        assertTrue(set.contains("c"));
    }
}
