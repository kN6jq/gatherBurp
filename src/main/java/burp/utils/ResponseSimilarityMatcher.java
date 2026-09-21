package burp.utils;

import java.util.*;

import java.util.regex.Pattern;

/** 响应相似度匹配器：预处理（去 HTML/时间戳/哈希/ID 等动态内容）后按 token 比较相似度。 */
public class ResponseSimilarityMatcher {
    /** 相似度阈值，可以根据实际测试调整 */
    private static final double SIMILARITY_THRESHOLD = 0.85;
    private static final int MIN_TOKEN_LENGTH = 4;
    /** 参与相似度计算的正文字符上限：预处理与分词开销随长度线性增长，超大响应截断防 CPU 爆炸。 */
    private static final int MAX_SIMILARITY_BODY_CHARS = 64 * 1024;

    /** 预编译的响应预处理正则模式集 */
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
     * 判断两个响应数据包的相似度关系（使用默认阈值0.85）
     * @return true 如果两个响应包差异显著（相似度低于阈值）
     */
    public static boolean compareTwoResponses(String response1, String response2) {
        return compareTwoResponses(response1, response2, SIMILARITY_THRESHOLD);
    }

    /**
     * 判断两个响应数据包的相似度关系
     * @param threshold 相似度阈值，低于此值视为差异显著
     * @return true 如果两个响应包差异显著（相似度低于阈值）
     */
    public static boolean compareTwoResponses(String response1, String response2, double threshold) {
        if (response1 == null || response2 == null) {
            return false;
        }
        double similarity = calculateSimilarity(response1, response2);
        return similarity < threshold;
    }

    /**
     * 判断三个响应包的相似度关系，用于SQL注入检测（使用默认阈值0.85）
     * @return true 如果response1和response3相似，且都与response2不相似
     */
    public static boolean compareThreeResponses(String response1, String response2, String response3) {
        return compareThreeResponses(response1, response2, response3, SIMILARITY_THRESHOLD);
    }

    /**
     * 判断三个响应包的相似度关系，用于SQL注入检测
     * @param threshold 相似度阈值
     * @return true 如果response1和response3相似，且都与response2不相似
     */
    public static boolean compareThreeResponses(String response1, String response2, String response3, double threshold) {
        if (response1 == null || response2 == null || response3 == null) {
            return false;
        }

        double similarity1_3 = calculateSimilarity(response1, response3);  // 正常响应相似度
        double similarity1_2 = calculateSimilarity(response1, response2);  // 与异常响应相似度
        double similarity2_3 = calculateSimilarity(response2, response3);  // 与异常响应相似度

        return similarity1_3 >= threshold &&
                similarity1_2 < threshold &&
                similarity2_3 < threshold;
    }

    /** 返回三响应两两相似度，供 SQL 盲注评分使用。 */
    public static SimilarityResult compareThreeResponsesDetailed(String original, String abnormal, String normal) {
        if (original == null || abnormal == null || normal == null) {
            return new SimilarityResult(0.0d, 0.0d, 0.0d);
        }
        return new SimilarityResult(
                calculateSimilarity(original, normal),
                calculateSimilarity(original, abnormal),
                calculateSimilarity(normal, abnormal));
    }
    /** 计算两响应的 Jaccard 相似度（截断超大正文 + 预处理 + token 集合交集/并集）。 */
    public static double calculateSimilarity(String str1, String str2) {
        str1 = preprocessResponse(truncateForSimilarity(str1));
        str2 = preprocessResponse(truncateForSimilarity(str2));

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

    /** 截断超大响应体（两侧同口径比较前固定片段，控制预处理与分词开销）。 */
    private static String truncateForSimilarity(String str) {
        if (str == null || str.length() <= MAX_SIMILARITY_BODY_CHARS) {
            return str;
        }
        return str.substring(0, MAX_SIMILARITY_BODY_CHARS);
    }

    /** 预处理响应内容（去 HTML 标签/动态内容/标点，转小写合并空白）。 */
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

    /** 分词处理：提取长度 >= 4 的词及滑动窗口子串。 */
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
