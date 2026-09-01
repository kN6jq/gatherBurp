package burp.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** JSON 字符串处理工具：对 JSON 中字符串类型值进行替换/追加（mode 0/1），
 *  支持批量 payload、指定数量单引号、自定义 payload 等场景。 */
public class JsonProcessorUtil {

    private static final Pattern JSON_NUMBER = Pattern.compile("-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?");

    /** JSON 参数处理结果（参数路径 + 修改后 JSON + 原始值）。 */
    public static class ProcessResult {
        private String paramPath;  // JSON 参数路径
        private String modifiedJson;  // 修改后的 JSON
        private final String originalValue;  // 该叶子的原始值（字符串形式），供上层区分数字/字符串叶子

        public ProcessResult(String paramPath, String modifiedJson) {
            this(paramPath, modifiedJson, null);
        }

        public ProcessResult(String paramPath, String modifiedJson, String originalValue) {
            this.paramPath = paramPath;
            this.modifiedJson = modifiedJson;
            this.originalValue = originalValue;
        }

        public String getParamPath() { return paramPath; }
        public String getModifiedJson() { return modifiedJson; }
        /** 叶子原始值的字符串形式；数字/布尔/null 叶子同样有值，无法确定时为 null。 */
        public String getOriginalValue() { return originalValue; }
    }
    /** 处理模式枚举：REPLACE(0) 替换 / APPEND(1) 追加。 */
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

    /** 处理单个 JSON 对象（布尔值控制模式：true=替换，false=追加）。 */
    public static List<String> process(Object jsonInput, String payload, boolean isDeleteOrigin) {
        return process(jsonInput, payload, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /** 处理 JSON 并返回带参数路径的结果（SQL 模块 payload 表格的 key 列来源）。 */
    public static List<ProcessResult> processWithPath(Object jsonInput, String payload, boolean isDeleteOrigin) {
        List<ProcessResult> results = new ArrayList<>();
        try {
            Object root;
            if (jsonInput instanceof JSONObject) {
                root = jsonInput;
            } else if (jsonInput instanceof String) {
                root = JSON.parse((String) jsonInput);
            } else {
                return results;
            }
            int mode = isDeleteOrigin ? 0 : 1;
            // 结构化步骤导航（等价 JSONPointer）：每个叶子的定位由"从根开始的 key/下标序列"表达，
            // 不再把路径字符串按 '.' 切分回解析，键名包含 '.' 时依然能准确定位。
            List<Object> steps = new ArrayList<>();
            if (root instanceof JSONObject) {
                processObjectWithPath((JSONObject) root, root, "", steps, payload, mode, results);
            } else if (root instanceof JSONArray) {
                processArrayWithPath((JSONArray) root, root, "", steps, payload, mode, results);
            }
        } catch (Exception e) {
            throw new JsonProcessingException("处理JSON时发生错误: " + e.getMessage(), e);
        }
        return results;
    }

    /** 在深克隆副本中按步骤序列导航到目标容器（JSONObject 或 JSONArray）。 */
    private static Object navigateBySteps(Object cloneRoot, List<Object> steps) {
        Object current = cloneRoot;
        for (Object step : steps) {
            if (current == null) {
                return null;
            }
            if (step instanceof String) {
                if (!(current instanceof JSONObject)) {
                    return null;
                }
                current = ((JSONObject) current).get((String) step);
            } else {
                if (!(current instanceof JSONArray)) {
                    return null;
                }
                current = ((JSONArray) current).get((Integer) step);
            }
        }
        return current;
    }

    private static List<Object> appendStep(List<Object> steps, Object step) {
        List<Object> child = new ArrayList<>(steps.size() + 1);
        child.addAll(steps);
        child.add(step);
        return child;
    }

    /** 在克隆副本中定位 key 的父对象并写入新值。 */
    private static void writeLeafInClone(Object cloneRoot, List<Object> parentSteps,
                                         String key, Object replacement) {
        Object parent = navigateBySteps(cloneRoot, parentSteps);
        if (parent instanceof JSONObject) {
            ((JSONObject) parent).put(key, replacement);
        }
    }

    /** 在克隆副本中定位数组元素父容器并按下标写入新值。 */
    private static void writeArrayLeafInClone(Object cloneRoot, List<Object> arraySteps,
                                              int index, Object replacement) {
        Object parent = navigateBySteps(cloneRoot, arraySteps);
        if (parent instanceof JSONArray && index < ((JSONArray) parent).size()) {
            ((JSONArray) parent).set(index, replacement);
        }
    }

    // 处理数组（支持数组嵌套数组的深层递归）
    private static void processArrayWithPath(JSONArray array, Object root,
                                             String path, List<Object> arraySteps,
                                             String payload, int mode,
                                             List<ProcessResult> results) {
        for (int i = 0; i < array.size(); i++) {
            Object item = array.get(i);
            String currentPath = path + "[" + i + "]";

            if (item instanceof String) {
                Object newRoot = deepClone(root);
                String originalValue = (String) item;
                writeArrayLeafInClone(newRoot, arraySteps, i, mode == 0 ? payload : originalValue + payload);
                results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot), originalValue));
            } else if (isJsonPrimitive(item)) {
                Object newRoot = deepClone(root);
                String originalValue = String.valueOf(item);
                writeArrayLeafInClone(newRoot, arraySteps, i,
                        buildPrimitiveReplacement(item, payload, mode));
                results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot), originalValue));
            } else if (item instanceof JSONObject) {
                processObjectWithPath(
                        (JSONObject) item,
                        root,
                        currentPath,
                        appendStep(arraySteps, i),
                        payload,
                        mode,
                        results
                );
            } else if (item instanceof JSONArray) {
                // 递归处理嵌套数组 [[...]]
                processArrayWithPath(
                        (JSONArray) item,
                        root,
                        currentPath,
                        appendStep(arraySteps, i),
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    // 新增带路径的处理方法
    private static void processObjectWithPath(JSONObject currentObject, Object root,
                                              String path, List<Object> parentSteps,
                                              String payload, int mode,
                                              List<ProcessResult> results) {
        for (String key : currentObject.keySet()) {
            Object value = currentObject.get(key);
            String currentPath = path.isEmpty() ? key : path + "." + key;

            if (value instanceof String) {
                Object newRoot = deepClone(root);
                writeLeafInClone(newRoot, parentSteps, key, mode == 0 ? payload : (String) value + payload);
                results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot), (String) value));
            } else if (isJsonPrimitive(value)) {
                Object newRoot = deepClone(root);
                writeLeafInClone(newRoot, parentSteps, key, buildPrimitiveReplacement(value, payload, mode));
                results.add(new ProcessResult(currentPath, JSON.toJSONString(newRoot), String.valueOf(value)));
            } else if (value instanceof JSONObject) {
                processObjectWithPath(
                        (JSONObject) value,
                        root,
                        currentPath,
                        appendStep(parentSteps, key),
                        payload,
                        mode,
                        results
                );
            } else if (value instanceof JSONArray) {
                processArrayWithPath(
                        (JSONArray) value,
                        root,
                        currentPath,
                        appendStep(parentSteps, key),
                        payload,
                        mode,
                        results
                );
            }
        }
    }

    /** 深克隆，根可能是对象或数组。 */
    private static Object deepClone(Object root) {
        return JSON.parse(JSON.toJSONString(root));
    }

    /** 处理单个 JSON 对象（枚举控制模式），每次只修改一个参数。 */
    public static List<String> process(Object jsonInput, String payload, ProcessMode mode) {
        try {
            List<Object> results = processJsonSingle(jsonInput, payload, mode.getCode());
            return convertResultsToString(results);
        } catch (Exception e) {
            throw new JsonProcessingException("处理JSON时发生错误: " + e.getMessage(), e);
        }
    }

    /** 批量处理 JSON 对象（布尔值控制模式）。 */
    public static List<String> processBatch(Object jsonInput, List<String> payloads, boolean isDeleteOrigin) {
        return processBatch(jsonInput, payloads, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /** 批量处理 JSON 对象（枚举控制模式）。 */
    public static List<String> processBatch(Object jsonInput, List<String> payloads, ProcessMode mode) {
        List<String> allResults = new ArrayList<>();
        for (String payload : payloads) {
            allResults.addAll(process(jsonInput, payload, mode));
        }
        return allResults;
    }

    /** 使用指定数量单引号处理 JSON（布尔值控制模式）。 */
    public static List<String> processWithQuotes(Object jsonInput, int quoteCount, boolean isDeleteOrigin) {
        return processWithQuotes(jsonInput, quoteCount, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /** 使用指定数量单引号处理 JSON（枚举控制模式）。 */
    public static List<String> processWithQuotes(Object jsonInput, int quoteCount, ProcessMode mode) {
        return process(jsonInput, generateQuotes(quoteCount), mode);
    }

    /** 批量处理指定数量单引号（布尔值控制模式）。 */
    public static List<String> processWithQuotesBatch(Object jsonInput, List<Integer> quoteCounts, boolean isDeleteOrigin) {
        return processWithQuotesBatch(jsonInput, quoteCounts, ProcessMode.fromBoolean(isDeleteOrigin));
    }

    /** 批量处理指定数量单引号（枚举控制模式）。 */
    public static List<String> processWithQuotesBatch(Object jsonInput, List<Integer> quoteCounts, ProcessMode mode) {
        List<String> allResults = new ArrayList<>();
        for (Integer count : quoteCounts) {
            allResults.addAll(processWithQuotes(jsonInput, count, mode));
        }
        return allResults;
    }

    /** 将结果列表转换为 JSON 字符串列表。 */
    private static List<String> convertResultsToString(List<Object> results) {
        List<String> stringResults = new ArrayList<>();
        for (Object result : results) {
            stringResults.add(JSON.toJSONString(result));
        }
        return stringResults;
    }

    /** 生成指定数量的单引号字符串。 */
    private static String generateQuotes(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append('\'');
        }
        return sb.toString();
    }

    /** 处理 JSON 数据（JSONObject 或 JSON 字符串）。 */
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

    /** 处理 JSON 对象中每个叶子节点（递归）。 */
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

    /** 处理 JSON 数组中每个元素（递归）。 */
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

    private static boolean isJsonPrimitive(Object value) {
        return value instanceof Number || value instanceof Boolean || value == null;
    }

    /** 保持合法 JSON：数字/布尔/null payload 使用原生类型，其余 payload 作为 JSON 字符串发送。 */
    private static Object buildPrimitiveReplacement(Object originalValue, String payload, int mode) {
        String candidate = mode == 0 ? payload : String.valueOf(originalValue) + payload;
        if (candidate != null && (JSON_NUMBER.matcher(candidate).matches()
                || "true".equalsIgnoreCase(candidate)
                || "false".equalsIgnoreCase(candidate)
                || "null".equalsIgnoreCase(candidate))) {
            try {
                return JSON.parse(candidate);
            } catch (Exception ignored) {
                // 解析失败时按字符串处理，保证请求仍是合法 JSON。
            }
        }
        return candidate == null ? "" : candidate;
    }

    /** 根据路径更新 JSON 对象中的值。 */
    private static void updateValueInPath(JSONObject root, String path, String key, Object replacement) {
        if (path.isEmpty()) {
            root.put(key, replacement);
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

        current.put(key, replacement);
    }

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

    /** 根据路径获取 JSON 数组。 */
    private static JSONArray getArrayByPath(JSONObject root, String path) {
        String[] parts = path.split("\\.");
        JSONObject current = root;

        for (int i = 0; i < parts.length - 1; i++) {
            current = current.getJSONObject(parts[i]);
            if (current == null) return null;
        }

        return current.getJSONArray(parts[parts.length - 1]);
    }

    /** 深度克隆 JSONObject。 */
    private static JSONObject cloneJsonObject(JSONObject original) {
        return JSON.parseObject(JSON.toJSONString(original));
    }

    /** JSON 处理异常类。 */
    public static class JsonProcessingException extends RuntimeException {
        public JsonProcessingException(String message, Throwable cause) {
            super(message, cause);
        }

        public JsonProcessingException(String message) {
            super(message);
        }
    }
}
