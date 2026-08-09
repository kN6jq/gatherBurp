package burp.utils;

import java.util.*;

import java.util.regex.Pattern;

public class ResponseSimilarityMatcher {
    // 相似度阈值，可以根据实际测试调整
    private static final double SIMILARITY_THRESHOLD = 0.85;
    private static final int MIN_TOKEN_LENGTH = 4;

    // Pre-compiled patterns for response preprocessing
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]+>");
    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile("\\d{10,}");
    private static final Pattern MD5_PATTERN = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern SHA1_PATTERN = Pattern.compile("[0-9a-f]{40}");
    private static final Pattern SHA256_PATTERN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern NUM_ID_PATTERN = Pattern.compile("id=\\d+");
    private static final Pattern DATE_PATTERN = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
    private static final Pattern TIME_PATTERN = Pattern.compile("\\d{2}:\\d{2}:\\d{2}");
    private static final Pattern NON_ALPHANUMERIC_PATTERN = Pattern.compile("[^a-zA-Z0-9\\u4e00-\\u9fa5]");
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");

    /**
     * 判断两个响应数据包的相似度关系
     * @return true 如果两个响应包差异显著（相似度低于阈值）
     */
    public static boolean compareTwoResponses(String response1, String response2) {
        if (response1 == null || response2 == null) {
            return false;
        }
        double similarity = calculateJaccardSimilarity(response1, response2);
        return similarity < SIMILARITY_THRESHOLD;
    }

    /**
     * 判断三个响应包的相似度关系，用于SQL注入检测
     * @return true 如果response1和response3相似，且都与response2不相似
     */
    public static boolean compareThreeResponses(String response1, String response2, String response3) {
        if (response1 == null || response2 == null || response3 == null) {
            return false;
        }

        double similarity1_3 = calculateJaccardSimilarity(response1, response3);  // 正常响应相似度
        double similarity1_2 = calculateJaccardSimilarity(response1, response2);  // 与异常响应相似度
        double similarity2_3 = calculateJaccardSimilarity(response2, response3);  // 与异常响应相似度

        return similarity1_3 >= SIMILARITY_THRESHOLD &&
                similarity1_2 < SIMILARITY_THRESHOLD &&
                similarity2_3 < SIMILARITY_THRESHOLD;
    }

    /**
     * 计算Jaccard相似度
     */
    private static double calculateJaccardSimilarity(String str1, String str2) {
        str1 = preprocessResponse(str1);
        str2 = preprocessResponse(str2);

        Set<String> set1 = tokenize(str1);
        Set<String> set2 = tokenize(str2);

        Set<String> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);

        Set<String> union = new HashSet<>(set1);
        union.addAll(set2);

        if (union.isEmpty()) {
            return 1.0;
        }

        return (double) intersection.size() / union.size();
    }

    /**
     * 预处理响应内容
     */
    private static String preprocessResponse(String response) {
        if (response == null) {
            return "";
        }

        String result = response;

        // 移除HTML标签
        result = HTML_TAG_PATTERN.matcher(result).replaceAll(" ");

        // 移除动态内容
        result = TIMESTAMP_PATTERN.matcher(result).replaceAll("");
        result = MD5_PATTERN.matcher(result).replaceAll("");
        result = SHA1_PATTERN.matcher(result).replaceAll("");
        result = SHA256_PATTERN.matcher(result).replaceAll("");
        result = NUM_ID_PATTERN.matcher(result).replaceAll("id=");
        result = DATE_PATTERN.matcher(result).replaceAll("");
        result = TIME_PATTERN.matcher(result).replaceAll("");

        // 移除标点和特殊字符
        result = NON_ALPHANUMERIC_PATTERN.matcher(result).replaceAll(" ");

        // 转小写并处理空格
        result = result.toLowerCase().replaceAll("\\s+", " ").trim();

        return result;
    }

    /**
     * 分词处理
     */
    private static Set<String> tokenize(String str) {
        Set<String> tokens = new HashSet<>();
        String[] words = str.split("\\s+");

        for (String word : words) {
            if (word.length() >= MIN_TOKEN_LENGTH) {
                tokens.add(word);
                if (word.length() > MIN_TOKEN_LENGTH * 2) {
                    for (int i = 0; i <= word.length() - MIN_TOKEN_LENGTH; i++) {
                        tokens.add(word.substring(i, i + MIN_TOKEN_LENGTH));
                    }
                }
            }
        }
        return tokens;
    }
}