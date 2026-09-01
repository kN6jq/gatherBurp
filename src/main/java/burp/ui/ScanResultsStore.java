package burp.ui;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * 扫描模块共用的有界结果存储。
 *
 * <p>各扫描 UI（Auth/Fastjson/Log4j/Perm/Route/Redirect）此前各自维护
 * "static List + synchronized + MAX_LOG_ENTRIES 淘汰 + 表格刷新"四件套，
 * 且清空按钮的加锁情况不一致。统一收口到本类：</p>
 *
 * <ul>
 *   <li>数据保存在内部 {@link #entries} 列表，列表对象本身作为监视器：
 *       外部读代码（Table model 等）沿用 {@code synchronized (store.list())} 模式，
 *       与本类 add/clear 互斥，兼容现有 model 实现；</li>
 *   <li>容量超限时淘汰最旧条目，防止长时间会话内存无限增长；</li>
 *   <li>变更后统一按 EDT 规则触发表格刷新（非 EDT 线程走 invokeLater）。</li>
 * </ul>
 */
public final class ScanResultsStore<T> {
    private final List<T> entries = new ArrayList<>();
    private final int maxEntries;
    private final Runnable refresh;

    /**
     * @param maxEntries 容量上限，超限淘汰最旧条目
     * @param refresh    数据变更后的表格刷新动作（在 EDT 上执行）
     */
    public ScanResultsStore(int maxEntries, Runnable refresh) {
        this.maxEntries = Math.max(1, maxEntries);
        this.refresh = refresh == null ? () -> { } : refresh;
    }

    /** 返回数据列表（同时也是外部 synchronized 使用的监视器）。 */
    public List<T> list() {
        return entries;
    }

    /** 锁内以当前 size 作为 id 构建条目并追加，超限淘汰最旧，随后刷新表格。返回分配到的 id。 */
    public int add(Function<Integer, T> entryFactory) {
        int id;
        synchronized (entries) {
            id = entries.size();
            entries.add(entryFactory.apply(id));
            trimIfOverflow();
        }
        refreshAfterMutation();
        return id;
    }

    /** 追加已构建好的条目（调用方自行确定 id 时）。 */
    public void add(T entry) {
        synchronized (entries) {
            entries.add(entry);
            trimIfOverflow();
        }
        refreshAfterMutation();
    }

    /** 线程安全清空（与 add 互斥）。 */
    public void clear() {
        synchronized (entries) {
            entries.clear();
        }
    }

    /** 当前条目数（锁内读取）。 */
    public int size() {
        synchronized (entries) {
            return entries.size();
        }
    }

    private void refreshAfterMutation() {
        if (SwingUtilities.isEventDispatchThread()) {
            refresh.run();
        } else {
            SwingUtilities.invokeLater(refresh);
        }
    }

    private void trimIfOverflow() {
        if (entries.size() > maxEntries) {
            entries.subList(0, entries.size() - maxEntries).clear();
        }
    }
}
