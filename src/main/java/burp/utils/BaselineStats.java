package burp.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** 重复基线请求的不可变统计数据（中位数/标准差/样本数/高方差/状态码稳定）。 */
public final class BaselineStats {
    private final long medianResponseTimeMs;
    private final double standardDeviationMs;
    private final int medianBodyLength;
    private final int bodyLengthStandardDeviation;
    private final String representativeBodyHash;
    private final int sampleCount;
    private final boolean highVariance;
    private final boolean statusStable;

    public BaselineStats(long medianResponseTimeMs,
                         double standardDeviationMs,
                         int medianBodyLength,
                         int bodyLengthStandardDeviation,
                         String representativeBodyHash,
                         int sampleCount,
                         boolean highVariance,
                         boolean statusStable) {
        this.medianResponseTimeMs = Math.max(0L, medianResponseTimeMs);
        this.standardDeviationMs = Math.max(0.0d, standardDeviationMs);
        this.medianBodyLength = Math.max(0, medianBodyLength);
        this.bodyLengthStandardDeviation = Math.max(0, bodyLengthStandardDeviation);
        this.representativeBodyHash = representativeBodyHash == null ? "" : representativeBodyHash;
        this.sampleCount = Math.max(0, sampleCount);
        this.highVariance = highVariance;
        this.statusStable = statusStable;
    }

    /** 从样本列表计算基线统计（中位数 + 标准差 + 方差判定）。 */
    public static BaselineStats calculate(List<Long> responseTimes,
                                          List<Integer> bodyLengths,
                                          List<String> bodyHashes,
                                          List<Integer> statusCodes,
                                          double varianceRatio) {
        List<Long> times = new ArrayList<>();
        if (responseTimes != null) {
            for (Long value : responseTimes) {
                if (value != null && value >= 0L) {
                    times.add(value);
                }
            }
        }
        List<Integer> lengths = new ArrayList<>();
        if (bodyLengths != null) {
            for (Integer value : bodyLengths) {
                if (value != null && value >= 0) {
                    lengths.add(value);
                }
            }
        }
        if (times.isEmpty()) {
            return new BaselineStats(0L, 0.0d, medianInt(lengths), stddevInt(lengths),
                    firstNonEmpty(bodyHashes), 0, false, statusesStable(statusCodes));
        }
        long medianTime = medianLong(times);
        double stddev = stddevLong(times);
        int medianLength = medianInt(lengths);
        int lengthStddev = stddevInt(lengths);
        double ratio = varianceRatio <= 0.0d ? 0.5d : varianceRatio;
        boolean highVariance = stddev > Math.max(1L, medianTime) * ratio;
        return new BaselineStats(medianTime, stddev, medianLength, lengthStddev,
                firstNonEmpty(bodyHashes), times.size(), highVariance, statusesStable(statusCodes));
    }

    /** 返回 long 列表的中位数。 */
    private static long medianLong(List<Long> values) {
        if (values == null || values.isEmpty()) return 0L;
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int middle = sorted.size() / 2;
        if ((sorted.size() & 1) == 1) return sorted.get(middle);
        return (sorted.get(middle - 1) + sorted.get(middle)) / 2L;
    }

    /** 返回 int 列表的中位数。 */
    private static int medianInt(List<Integer> values) {
        if (values == null || values.isEmpty()) return 0;
        List<Integer> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int middle = sorted.size() / 2;
        if ((sorted.size() & 1) == 1) return sorted.get(middle);
        return (sorted.get(middle - 1) + sorted.get(middle)) / 2;
    }

    /** 返回 long 列表的标准差。 */
    private static double stddevLong(List<Long> values) {
        if (values == null || values.size() < 2) return 0.0d;
        double mean = 0.0d;
        for (Long value : values) mean += value;
        mean /= values.size();
        double sum = 0.0d;
        for (Long value : values) {
            double delta = value - mean;
            sum += delta * delta;
        }
        return Math.sqrt(sum / values.size());
    }

    /** 返回 int 列表的标准差。 */
    private static int stddevInt(List<Integer> values) {
        if (values == null || values.size() < 2) return 0;
        double mean = 0.0d;
        for (Integer value : values) mean += value;
        mean /= values.size();
        double sum = 0.0d;
        for (Integer value : values) {
            double delta = value - mean;
            sum += delta * delta;
        }
        return (int) Math.round(Math.sqrt(sum / values.size()));
    }

    /** 判断状态码列表是否全部一致。 */
    private static boolean statusesStable(List<Integer> statuses) {
        if (statuses == null || statuses.isEmpty()) return true;
        Integer first = null;
        for (Integer status : statuses) {
            if (status == null) continue;
            if (first == null) first = status;
            else if (!first.equals(status)) return false;
        }
        return true;
    }

    /** 返回列表中首个非空非空串值。 */
    private static String firstNonEmpty(List<String> values) {
        if (values != null) {
            for (String value : values) if (value != null && !value.isEmpty()) return value;
        }
        return "";
    }

    public long getMedianResponseTimeMs() { return medianResponseTimeMs; }
    public double getStandardDeviationMs() { return standardDeviationMs; }
    public int getMedianBodyLength() { return medianBodyLength; }
    public int getBodyLengthStandardDeviation() { return bodyLengthStandardDeviation; }
    public String getRepresentativeBodyHash() { return representativeBodyHash; }
    public int getSampleCount() { return sampleCount; }
    public boolean isHighVariance() { return highVariance; }
    public boolean isStatusStable() { return statusStable; }
}
