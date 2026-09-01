package burp.utils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * 容量上限的线程安全 LRU 集合。
 *
 * <p>add 语义与 {@link java.util.Set#add} 一致：元素已存在返回 false。
 * 容量耗尽时按访问序淘汰最旧元素，用于去重键（URL 特征、issue 键）的内存上限保护。</p>
 */
public final class LruSet<E> {
    private static final Object PRESENT = new Object();

    private final LinkedHashMap<E, Object> map;
    private final int maxSize;

    public LruSet(int maxSize) {
        this.maxSize = Math.max(1, maxSize);
        this.map = new LinkedHashMap<E, Object>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<E, Object> eldest) {
                return size() > LruSet.this.maxSize;
            }
        };
    }

    /** 元素已存在返回 false（此时仅刷新访问序），新增返回 true。 */
    public synchronized boolean add(E element) {
        return map.put(element, PRESENT) == null;
    }

    public synchronized boolean contains(E element) {
        return map.containsKey(element);
    }

    public synchronized boolean remove(E element) {
        return map.remove(element) != null;
    }

    public synchronized void clear() {
        map.clear();
    }

    public synchronized int size() {
        return map.size();
    }

    /** 淘汰所有匹配的元素，返回删除数量。 */
    public synchronized int removeIfMatch(Predicate<? super E> predicate) {
        List<E> matched = new ArrayList<>();
        for (E element : map.keySet()) {
            if (predicate.test(element)) {
                matched.add(element);
            }
        }
        for (E element : matched) {
            map.remove(element);
        }
        return matched.size();
    }
}
