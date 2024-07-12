package burp.utils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JsonUtils {
    public static List<Object> updateJsonObjectFromStr(Object baseObj, String updateStr, int mode) {
        List<Object> resultList = new ArrayList<>();

        if (mode == 0) {
            resultList.add(replaceUpdate(baseObj, updateStr));
        } else if (mode == 1) {
            resultList.add(appendUpdate(baseObj, updateStr));
        } else {
            throw new IllegalArgumentException("Invalid mode: " + mode);
        }

        return resultList;
    }

    private static Object replaceUpdate(Object obj, String updateStr) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            Map<String, Object> updatedMap = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                updatedMap.put(entry.getKey(), replaceUpdate(entry.getValue(), updateStr));
            }
            return updatedMap;
        } else if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> updatedList = new ArrayList<>();
            for (Object item : list) {
                updatedList.add(replaceUpdate(item, updateStr));
            }
            return updatedList;
        } else if (obj instanceof String) {
            return updateStr;
        } else if (obj instanceof Integer) {
            return obj;
        } else if (obj instanceof Double) {
            return obj;
        } else if (obj instanceof Long) {
            return obj;
        }else if (obj instanceof Boolean) {
            return obj;
        } else {
            throw new IllegalArgumentException("Unsupported data type: " + obj.getClass().getName());
        }
    }

    private static Object appendUpdate(Object obj, String updateStr) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            Map<String, Object> updatedMap = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                updatedMap.put(entry.getKey(), appendUpdate(entry.getValue(), updateStr));
            }
            return updatedMap;
        } else if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> updatedList = new ArrayList<>();
            for (Object item : list) {
                updatedList.add(appendUpdate(item, updateStr));
            }
            return updatedList;
        } else if (obj instanceof String) {
            return obj.toString() + updateStr;
        } else if (obj instanceof Integer) {
            return obj;
        } else if (obj instanceof Double) {
            return obj;
        } else if (obj instanceof Long) {
            return obj;
        }else if (obj instanceof Boolean) {
            return obj;
        }else {
            throw new IllegalArgumentException("Unsupported data type: " + obj.getClass().getName());
        }
    }
}
