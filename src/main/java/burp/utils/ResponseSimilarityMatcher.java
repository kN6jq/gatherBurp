package burp.utils;

import java.util.*;

public class ResponseSimilarityMatcher {
    // 相似度阈值，可以根据需要调整
    private static final double SIMILARITY_THRESHOLD = 0.85;

    /**
     * 判断三个响应数据包的相似度关系
     * @param response1 第一个响应数据包
     * @param response2 第二个响应数据包（异常响应）
     * @param response3 第三个响应数据包
     * @return 如果response1和response3相似，且都与response2不相似，返回true
     */
    public static boolean compareResponses(String response1, String response2, String response3) {
        double similarity1_3 = calculateJaccardSimilarity(response1, response3);
        double similarity1_2 = calculateJaccardSimilarity(response1, response2);
        double similarity2_3 = calculateJaccardSimilarity(response2, response3);

        // response1 和 response3 相似，且都与 response2 不相似
        return similarity1_3 >= SIMILARITY_THRESHOLD &&
                similarity1_2 < SIMILARITY_THRESHOLD &&
                similarity2_3 < SIMILARITY_THRESHOLD;
    }

    /**
     * 计算两个字符串的Jaccard相似度
     */
    private static double calculateJaccardSimilarity(String str1, String str2) {
        Set<String> set1 = tokenize(str1);
        Set<String> set2 = tokenize(str2);

        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        return union.isEmpty() ? 0 : (double) intersection.size() / union.size();
    }

    /**
     * 将字符串分割成token集合
     */
    private static Set<String> tokenize(String str) {
        // 移除HTML标签
        str = str.replaceAll("<[^>]*>", "");
        // 移除特殊字符
        str = str.replaceAll("[^a-zA-Z0-9\\u4e00-\\u9fa5]", " ");
        // 转换为小写并分割
        String[] tokens = str.toLowerCase().split("\\s+");
        return new HashSet<>(Arrays.asList(tokens));
    }

    /**
     * 获取响应内容的摘要特征
     */
    private static String getResponseDigest(String response) {
        // 移除动态内容（如时间戳、随机值等）
        response = response.replaceAll("\\d{10,}", ""); // 移除长数字
        response = response.replaceAll("[0-9a-f]{32}", ""); // 移除MD5等哈希
        return response;
    }

    /**
     * 使用汉明距离计算相似度（可选的补充方法）
     */
    private static double calculateHammingDistance(String str1, String str2) {
        if (str1.length() != str2.length()) {
            return 0;
        }

        int distance = 0;
        for (int i = 0; i < str1.length(); i++) {
            if (str1.charAt(i) != str2.charAt(i)) {
                distance++;
            }
        }

        return 1.0 - ((double) distance / str1.length());
    }

    /**
     * 详细的相似度分析结果
     */
    public static class SimilarityResult {
        private final double jaccardSimilarity;
        private final double hammingDistance;
        private final boolean isSimilar;

        public SimilarityResult(double jaccardSimilarity, double hammingDistance) {
            this.jaccardSimilarity = jaccardSimilarity;
            this.hammingDistance = hammingDistance;
            this.isSimilar = jaccardSimilarity >= SIMILARITY_THRESHOLD;
        }

        public double getJaccardSimilarity() {
            return jaccardSimilarity;
        }

        public double getHammingDistance() {
            return hammingDistance;
        }

        public boolean isSimilar() {
            return isSimilar;
        }
    }

    /**
     * 获取详细的相似度分析结果
     */
    public static SimilarityResult analyzeSimilarity(String response1, String response2) {
        double jaccard = calculateJaccardSimilarity(response1, response2);
        double hamming = calculateHammingDistance(
                getResponseDigest(response1),
                getResponseDigest(response2)
        );
        return new SimilarityResult(jaccard, hamming);
    }
}
