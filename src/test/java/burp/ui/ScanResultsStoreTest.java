package burp.ui;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

public class ScanResultsStoreTest {

    @Test
    public void evictsOldestEntriesBeyondCapacity() {
        ScanResultsStore<String> store = new ScanResultsStore<>(3, () -> { });
        for (int i = 0; i < 5; i++) {
            store.add("v" + i);
        }
        assertEquals(3, store.size());
        List<String> list = store.list();
        synchronized (list) {
            assertEquals("v2", list.get(0));
            assertEquals("v3", list.get(1));
            assertEquals("v4", list.get(2));
        }
    }

    @Test
    public void idFactoryReceivesSequentialIdsAndListIsExposedAsMonitor() {
        ScanResultsStore<String> store = new ScanResultsStore<>(10, () -> { });
        int firstId = store.add(value -> "id" + value);
        int secondId = store.add(value -> "id" + value);
        assertEquals(0, firstId);
        assertEquals(1, secondId);
        // 外部读代码（Table model）以 store.list() 作为监视器，与 add 互斥
        List<String> list = store.list();
        synchronized (list) {
            assertEquals("id0", list.get(0));
            assertEquals("id1", list.get(1));
        }
        assertSame(list, store.list());
    }

    @Test
    public void clearRemovesAllEntries() {
        ScanResultsStore<String> store = new ScanResultsStore<>(10, () -> { });
        store.add("a");
        store.add("b");
        store.clear();
        assertEquals(0, store.size());
    }
}
