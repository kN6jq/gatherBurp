package burp.utils;

/** 每参数主请求预算（已用/剩余计数器，线程安全）。 */
public final class ScanBudget {
    private final int maximum;
    private int used;

    public ScanBudget(int maximum) {
        this.maximum = Math.max(0, maximum);
    }

    /** 尝试获取一个请求配额，成功返回 true，预算耗尽返回 false。 */
    public synchronized boolean tryAcquire() {
        if (used >= maximum) return false;
        used++;
        return true;
    }

    public synchronized int getUsed() { return used; }
    public synchronized int getRemaining() { return Math.max(0, maximum - used); }
}
