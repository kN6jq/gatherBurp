package burp.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON字符串处理工具类
 * 支持对JSON字符串中的字符串类型值进行修改
 *
 * 使用示例:
 * 1. 使用布尔值控制模式（推荐）:
 *    boolean isDeleteOrigin = true; // true表示替换模式，false表示追加模式
 *    // 处理单引号
 *    List<String> results1 = JsonProcessorUtil.processBatch(
 *        jsonInput, Arrays.asList("'"), isDeleteOrigin);
 *
 *    // 处理指定数量的单引号
 *    List<String> results2 = JsonProcessorUtil.processWithQuotes(
 *        jsonInput, 2, isDeleteOrigin);
 *
 *    // 批量处理多个数量的单引号
 *    List<String> results3 = JsonProcessorUtil.processWithQuotesBatch(
 *        jsonInput, Arrays.asList(1, 2, 3), isDeleteOrigin);
 *
 * 2. 使用ProcessMode枚举:
 *    // 单个处理
 *    List<String> results1 = JsonProcessorUtil.processWithQuotes(
 *        jsonInput, 2, ProcessMode.APPEND);
 *
 *    // 批量处理
 *    List<String> results2 = JsonProcessorUtil.processWithQuotesBatch(
 *        jsonInput, Arrays.asList(1, 2, 3), ProcessMode.APPEND);
 *
 *    // 自定义payload
 *    List<String> results3 = JsonProcessorUtil.processBatch(
 *        jsonInput, Arrays.asList("'", "''"), ProcessMode.APPEND);
 */
public class JsonProcessorUtil {

    // 结果类
    public static class ProcessResult {
        private String paramPath;  // JSON 参数路径
        private String modifiedJson;  // 修改后的 JSON

        public ProcessResult(String paramPath, String modifiedJson) {
            this.paramPath = paramPath;
            this.modifiedJson = modifiedJson;
        }

        public String getParamPath() { return paramPath; }
        public String getModifiedJson() { return modifiedJson; }
    }
    /**
     * 处理模式枚举
     */
    public enum ProcessMode {
        REPLACE(0, "替换模式"),
        APPEND(1, "追加模式");

        private final int code;
        private final String description;

        ProcessMode(int code, String description) {
            this.code = code;
            this.description = description;
        }

        public int getCode() {
            return code;
        }

        public String getDescription() {
            return description;
        }

        // 转换为布尔值
        public boolean toBoolean() {
            return this == REPLACE;
        }

        // 从布尔值获取模式
        public static ProcessMode fromBoolean(boolean isDeleteOrigin) {
            return isDeleteOrigin ? REPLACE : APPEND;
        }
    }

    /**
     * 处理单个JSON对象（使用布尔值控制模式）
     *
     * @param jsonInput JSON输入（字符串或JSONObject）
     * @param payload 要插入的内容
     * @param isDeleteOrigin true表示替换模式，false表示追加模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> process(Object jsonInput, String payload, boolean isDeleteOrigin) {
        return process(jsonInput, payload, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    // 修改 process 方法返回带路径信息的结果
    public static List<ProcessResult> processWithPath(Object jsonInput, String payload, boolean isDeleteOrigin) {
        List<ProcessResult> results = new ArrayList<>();
        try {
            if (jsonInput instanceof JSONObject) {
                processJsonObjectWithPath((JSONObject) jsonInput, null, "", payload,
                        isDeleteOrigin ? 0 : 1, results);
            } else if (jsonInput instanceof String) {
                Object parsedJson = JSON.parse((String) jsonInput);
                return processWithPath(parsedJson, payload, isDeleteOrigin);
            }
        } catch (Exception e) {
            throw new JsonProcessingException("处理JSON时发生错误: " + e.getMessage(), e);
        }
        return results;
    }
    // 新增处理数组的方法
    private static void processArrayWithPath(JSONArray array, JSONObject root,
                                             String path, String payload, int mode,
                                             List<ProcessResult> results) {
        for (int i = 0; i < array.size(); i++) {
            Object item = array.get(i);
            String currentPath = path + "[" + i + "]";

            if (item instanceof String) {
                JSONObject newRoot = cloneJsonObject(root);
                JSONArray targetArray = getArrayByPath(newRoot, path);
                if (targetArray != null) {
                    String originalValue = (String) item;
                    targetArray.set(i, mode == 0 ? payload : originalValue + payload);
                    results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot)));
                }
            } else if (item instanceof JSONObject) {
                processJsonObjectWithPath(
                        (JSONObject) item,
                        root,
                        currentPath,
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    // 新增带路径的处理方法
    private static void processJsonObjectWithPath(JSONObject currentObject, JSONObject root,
                                                  String path, String payload, int mode,
                                                  List<ProcessResult> results) {
        for (String key : currentObject.keySet()) {
            Object value = currentObject.get(key);
            String currentPath = path.isEmpty() ? key : path + "." + key;

            if (value instanceof String) {
                JSONObject newRoot = root == null ?
                        cloneJsonObject(currentObject) : cloneJsonObject(root);
                updateValueInPath(newRoot, path, key, (String) value, payload, mode);
                results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot)));
            } else if (value instanceof JSONObject) {
                processJsonObjectWithPath(
                        (JSONObject) value,
                        root == null ? currentObject : root,
                        currentPath,
                        payload,
                        mode,
                        results
                );
            } else if (value instanceof JSONArray) {
                processArrayWithPath(
                        (JSONArray) value,
                        root == null ? currentObject : root,
                        currentPath,
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    /**
     * 处理单个JSON对象，每次只修改一个参数
     *
     * @param jsonInput JSON输入（字符串或JSONObject）
     * @param payload 要插入的内容
     * @param mode 处理模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> process(Object jsonInput, String payload, ProcessMode mode) {
        try {
            List<Object> results = processJsonSingle(jsonInput, payload, mode.getCode());
            return convertResultsToString(results);
        } catch (Exception e) {
            throw new JsonProcessingException("处理JSON时发生错误: " + e.getMessage(), e);
        }
    }

    /**
     * 批量处理JSON对象（使用布尔值控制模式）
     *
     * @param jsonInput JSON输入
     * @param payloads 要插入的内容列表
     * @param isDeleteOrigin true表示替换模式，false表示追加模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processBatch(Object jsonInput, List<String> payloads, boolean isDeleteOrigin) {
        return processBatch(jsonInput, payloads, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /**
     * 批量处理JSON对象
     *
     * @param jsonInput JSON输入
     * @param payloads 要插入的内容列表
     * @param mode 处理模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processBatch(Object jsonInput, List<String> payloads, ProcessMode mode) {
        List<String> allResults = new ArrayList<>();
        for (String payload : payloads) {
            allResults.addAll(process(jsonInput, payload, mode));
        }
        return allResults;
    }

    /**
     * 使用指定数量的单引号处理JSON（使用布尔值控制模式）
     *
     * @param jsonInput JSON输入
     * @param quoteCount 单引号数量
     * @param isDeleteOrigin true表示替换模式，false表示追加模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processWithQuotes(Object jsonInput, int quoteCount, boolean isDeleteOrigin) {
        return processWithQuotes(jsonInput, quoteCount, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /**
     * 使用指定数量的单引号处理JSON
     *
     * @param jsonInput JSON输入
     * @param quoteCount 单引号数量
     * @param mode 处理模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processWithQuotes(Object jsonInput, int quoteCount, ProcessMode mode) {
        return process(jsonInput, generateQuotes(quoteCount), mode);
    }

    /**
     * 批量处理指定数量的单引号（使用布尔值控制模式）
     *
     * @param jsonInput JSON输入
     * @param quoteCounts 单引号数量列表
     * @param isDeleteOrigin true表示替换模式，false表示追加模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processWithQuotesBatch(Object jsonInput, List<Integer> quoteCounts, boolean isDeleteOrigin) {
        return processWithQuotesBatch(jsonInput, quoteCounts, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /**
     * 批量处理指定数量的单引号
     *
     * @param jsonInput JSON输入
     * @param quoteCounts 单引号数量列表
     * @param mode 处理模式
     * @return 处理后的JSON字符串列表
     */
    public static List<String> processWithQuotesBatch(Object jsonInput, List<Integer> quoteCounts, ProcessMode mode) {
        List<String> allResults = new ArrayList<>();
        for (Integer count : quoteCounts) {
            allResults.addAll(processWithQuotes(jsonInput, count, mode));
        }
        return allResults;
    }

    /**
     * 将结果转换为字符串列表
     */
    private static List<String> convertResultsToString(List<Object> results) {
        List<String> stringResults = new ArrayList<>();
        for (Object result : results) {
            stringResults.add(JSON.toJSONString(result));
        }
        return stringResults;
    }

    /**
     * 生成指定数量的单引号
     */
    private static String generateQuotes(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append('\'');
        }
        return sb.toString();
    }

    /**
     * 处理JSON数据
     */
    private static List<Object> processJsonSingle(Object jsonData, String payload, int mode) {
        List<Object> results = new ArrayList<>();
        if (jsonData instanceof JSONObject) {
            processJsonObject((JSONObject) jsonData, null, "", payload, mode, results);
        } else if (jsonData instanceof String) {
            try {
                Object parsedJson = JSON.parse((String) jsonData);
                return processJsonSingle(parsedJson, payload, mode);
            } catch (Exception e) {
                throw new JsonProcessingException("无效的JSON字符串", e);
            }
        }
        return results;
    }

    /**
     * 处理JSON对象
     */
    private static void processJsonObject(JSONObject currentObject, JSONObject root,
                                          String path, String payload, int mode,
                                          List<Object> results) {
        for (String key : currentObject.keySet()) {
            Object value = currentObject.get(key);
            String currentPath = path.isEmpty() ? key : path + "." + key;

            if (value instanceof String) {
                JSONObject newRoot = root == null ?
                        cloneJsonObject(currentObject) : cloneJsonObject(root);
                updateValueInPath(newRoot, path, key, (String) value, payload, mode);
                results.add(newRoot);
            } else if (value instanceof JSONObject) {
                processJsonObject(
                        (JSONObject) value,
                        root == null ? currentObject : root,
                        currentPath,
                        payload,
                        mode,
                        results
                );
            } else if (value instanceof JSONArray) {
                processArray(
                        (JSONArray) value,
                        root == null ? currentObject : root,
                        currentPath,
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    /**
     * 处理JSON数组
     */
    private static void processArray(JSONArray array, JSONObject root,
                                     String path, String payload, int mode,
                                     List<Object> results) {
        for (int i = 0; i < array.size(); i++) {
            Object item = array.get(i);
            if (item instanceof String) {
                JSONObject newRoot = cloneJsonObject(root);
                JSONArray targetArray = getArrayByPath(newRoot, path);
                if (targetArray != null) {
                    targetArray.set(i, mode == 0 ? payload : item + payload);
                    results.add(newRoot);
                }
            } else if (item instanceof JSONObject) {
                processJsonObject(
                        (JSONObject) item,
                        root,
                        path + "[" + i + "]",
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    /**
     * 根据路径更新值
     */
    private static void updateValueInPath(JSONObject root, String path, String key,
                                          String originalValue, String payload, int mode) {
        if (path.isEmpty()) {
            root.put(key, mode == 0 ? payload : originalValue + payload);
            return;
        }

        String[] parts = path.split("\\.");
        JSONObject current = root;

        for (String part : parts) {
            if (part.contains("[") && part.contains("]")) {
                String arrayKey = part.substring(0, part.indexOf("["));
                int index = Integer.parseInt(part.substring(
                        part.indexOf("[") + 1, part.indexOf("]")));
                JSONArray array = current.getJSONArray(arrayKey);
                current = array.getJSONObject(index);
            } else {
                current = current.getJSONObject(part);
            }
        }

        current.put(key, mode == 0 ? payload : originalValue + payload);
    }

    /**
     * 根据路径获取数组
     */
    private static JSONArray getArrayByPath(JSONObject root, String path) {
        String[] parts = path.split("\\.");
        JSONObject current = root;

        for (int i = 0; i < parts.length - 1; i++) {
            current = current.getJSONObject(parts[i]);
            if (current == null) return null;
        }

        return current.getJSONArray(parts[parts.length - 1]);
    }

    /**
     * 深度克隆JSONObject
     */
    private static JSONObject cloneJsonObject(JSONObject original) {
        return JSON.parseObject(JSON.toJSONString(original));
    }

    /**
     * JSON处理异常类
     */
    public static class JsonProcessingException extends RuntimeException {
        public JsonProcessingException(String message, Throwable cause) {
            super(message, cause);
        }

        public JsonProcessingException(String message) {
            super(message);
        }
    }
}
