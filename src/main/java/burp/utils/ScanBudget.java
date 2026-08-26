package burp.utils;

/** Per-parameter primary request budget. */
public final class ScanBudget {
    private final int maximum;
    private int used;

    public ScanBudget(int maximum) {
        this.maximum = Math.max(0, maximum);
    }

    public synchronized boolean tryAcquire() {
        if (used >= maximum) return false;
        used++;
        return true;
    }

    public synchronized int getUsed() { return used; }
    public synchronized int getRemaining() { return Math.max(0, maximum - used); }
}
