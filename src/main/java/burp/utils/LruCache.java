package burp.utils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * 容量上限的线程安全 LRU 缓存。
 *
 * <p>扫描线程池多线程读写，所有访问走同一把锁；容量耗尽时按访问序淘汰最旧条目，
 * 防止长时间被动扫描下按 logid/位置索引的基线与证据状态无限增长。
 * 仅用于内存态缓存，不承担持久化职责。</p>
 */
public final class LruCache<K, V> {
    private final LinkedHashMap<K, V> map;
    private final int maxSize;

    public LruCache(int maxSize) {
        this.maxSize = Math.max(1, maxSize);
        this.map = new LinkedHashMap<K, V>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > LruCache.this.maxSize;
            }
        };
    }

    public synchronized V get(K key) {
        return map.get(key);
    }

    public synchronized V put(K key, V value) {
        return map.put(key, value);
    }

    public synchronized V remove(K key) {
        return map.remove(key);
    }

    public synchronized boolean containsKey(K key) {
        return map.containsKey(key);
    }

    public synchronized void clear() {
        map.clear();
    }

    public synchronized int size() {
        return map.size();
    }

    public synchronized V computeIfAbsent(K key, Function<? super K, ? extends V> mappingFunction) {
        V value = map.get(key);
        if (value == null) {
            value = mappingFunction.apply(key);
            if (value != null) {
                map.put(key, value);
            }
        }
        return value;
    }

    /** 淘汰所有匹配的键（用于按 logid 前缀清理），返回删除数量。 */
    public synchronized int removeKeys(Predicate<? super K> predicate) {
        List<K> matched = new ArrayList<>();
        for (K key : map.keySet()) {
            if (predicate.test(key)) {
                matched.add(key);
            }
        }
        for (K key : matched) {
            map.remove(key);
        }
        return matched.size();
    }
}
