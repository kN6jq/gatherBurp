package burp.utils;

import burp.IRequestInfo;
import burp.IResponseInfo;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.mozilla.universalchardet.UniversalDetector;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 编码转换工具，支撑消息编辑器的 U2C 附属页签：探测编码、解码 Unicode 转义、JSON 美化自动转中文。
 *  编码探测顺序：Content-Type 的 charset → juniversalchardet 字节识别 → 调用方按候选列表兜底。 */
public class CodecUtils {
    /** 常用中文编码候选，排在探测结果之后供"切换编码"轮换。 */
    public static final String[] FALLBACK_CHARSETS = {"UTF-8", "GBK", "GB2312", "GB18030", "Big5", "Big5-HKSCS", "UTF-16"};
    public static final String SYSTEM_CHARSET = Charset.defaultCharset().name();

    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9a-fA-F]{4})|\\\\\\\\");

    /** 编码候选列表：探测结果在前、常用编码在后，去重保序。 */
    public static List<String> buildCharsetCandidates(byte[] content) {
        List<String> candidates = new ArrayList<>();
        String detected = detectCharset(content);
        if (detected != null && Charset.isSupported(detected)) {
            candidates.add(detected);
        }
        for (String name : FALLBACK_CHARSETS) {
            if (!candidates.contains(name)) {
                candidates.add(name);
            }
        }
        return candidates;
    }

    /** 探测消息编码：先看 Content-Type 的 charset，再用字节特征识别；都失败返回 null。 */
    public static String detectCharset(byte[] content) {
        if (content == null || content.length == 0) {
            return null;
        }
        boolean isResponse = startsWithHttpLine(content);
        String contentType = getHeaderValue(content, isResponse);
        if (contentType != null) {
            String name = extractCharsetParam(contentType);
            if (name != null) {
                return name;
            }
        }
        UniversalDetector detector = new UniversalDetector(null);
        try {
            detector.handleData(content, 0, content.length);
            detector.dataEnd();
            return detector.getDetectedCharset();
        } catch (Exception e) {
            return null;
        } finally {
            detector.reset();
        }
    }

    /** 是否包含待解码的 Unicode 转义（含被双反斜杠转义的形式）。 */
    public static boolean containsUnicodeEscape(String text) {
        return text != null && UNICODE_ESCAPE.matcher(text).find();
    }

    /** 解一层转义：Unicode 转义转成对应字符，双反斜杠还原为单反斜杠（其余转义保留，显示用途足够）。 */
    public static String unescapeUnicode(String text) {
        if (text == null) {
            return null;
        }
        Matcher matcher = UNICODE_ESCAPE.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            // group(1) 有值是 Unicode 转义，否则命中双反斜杠分支;quoteReplacement 防止 $ 等字符被当正则特殊符号
            matcher.appendReplacement(sb, Matcher.quoteReplacement(matcher.group(1) != null
                    ? String.valueOf((char) Integer.parseInt(matcher.group(1), 16))
                    : "\\"));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /** 连续解多层转义（内容被双重转义时），最多 maxRounds 轮。 */
    public static String unescapeRepeatedly(String text, int maxRounds) {
        for (int i = 0; i < maxRounds && containsUnicodeEscape(text); i++) {
            text = unescapeUnicode(text);
        }
        return text;
    }

    /** JSON 美化（解析后重排，Unicode 转义自动转为实际字符）；非合法 JSON 返回 null。 */
    public static String prettyJson(String text) {
        try {
            return JSON.toJSONString(JSON.parse(text), SerializerFeature.PrettyFormat,
                    SerializerFeature.WriteMapNullValue, SerializerFeature.DisableCircularReferenceDetect);
        } catch (Exception e) {
            return null;
        }
    }

    /** 按指定编码解释原始字节并做显示层处理：含 Unicode 转义时优先整包 JSON 美化，
     *  失败再逐层解码转义；返回值仍是以 charset 编码的字节，无转义时原样返回。 */
    public static byte[] buildDisplayContent(byte[] content, boolean isRequest, String charset) {
        try {
            String text = new String(content, charset);
            if (!containsUnicodeEscape(text)) {
                return content;
            }
            if (isJson(content, isRequest)) {
                byte[] prettyMessage = buildPrettyJsonMessage(content, isRequest, charset);
                if (prettyMessage != null) {
                    return prettyMessage;
                }
            }
            return unescapeRepeatedly(text, 3).getBytes(charset);
        } catch (Exception e) {
            return content;
        }
    }

    /** 把以 originalCharset 编码的字节转码为 newCharset，编码不支持时原样返回。 */
    public static byte[] convertCharset(byte[] content, String originalCharset, String newCharset) {
        try {
            return new String(content, originalCharset).getBytes(newCharset);
        } catch (Exception e) {
            return content;
        }
    }

    private static boolean startsWithHttpLine(byte[] content) {
        int len = Math.min(content.length, 5);
        return new String(content, 0, len, Charset.forName("US-ASCII")).startsWith("HTTP/");
    }

    /** 取头值；请求/响应分别用对应的分析入口，解析失败返回 null。 */
    private static String getHeaderValue(byte[] content, boolean isResponse) {
        try {
            List<String> headers = isResponse
                    ? Utils.helpers.analyzeResponse(content).getHeaders()
                    : Utils.helpers.analyzeRequest(content).getHeaders();
            for (String header : headers) {
                int idx = header.indexOf(':');
                if (idx > 0 && header.substring(0, idx).trim().equalsIgnoreCase("Content-Type")) {
                    return header.substring(idx + 1).trim();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /** 从 Content-Type 值里抠出 charset 参数（去掉引号与后续参数），不存在或不支持返回 null。 */
    private static String extractCharsetParam(String contentType) {
        int idx = contentType.toLowerCase().indexOf("charset=");
        if (idx < 0) {
            return null;
        }
        String raw = contentType.substring(idx + "charset=".length()).trim();
        int end = raw.indexOf(';');
        String name = (end >= 0 ? raw.substring(0, end) : raw).trim().replace("\"", "");
        return !name.isEmpty() && Charset.isSupported(name) ? name : null;
    }

    private static boolean isJson(byte[] content, boolean isRequest) {
        try {
            if (isRequest) {
                return Utils.helpers.analyzeRequest(content).getContentType() == IRequestInfo.CONTENT_TYPE_JSON;
            }
            String mimeType = Utils.helpers.analyzeResponse(content).getInferredMimeType();
            if (mimeType != null && mimeType.toLowerCase().contains("json")) {
                return true;
            }
            String contentType = getHeaderValue(content, true);
            return contentType != null && contentType.toLowerCase().contains("json");
        } catch (Exception e) {
            return false;
        }
    }

    /** 只美化消息体并按原头重建消息；任何一步失败返回 null（调用方走逐层解码兜底）。 */
    private static byte[] buildPrettyJsonMessage(byte[] content, boolean isRequest, String charset) {
        try {
            int bodyOffset;
            List<String> headers;
            if (isRequest) {
                IRequestInfo info = Utils.helpers.analyzeRequest(content);
                bodyOffset = info.getBodyOffset();
                headers = info.getHeaders();
            } else {
                IResponseInfo info = Utils.helpers.analyzeResponse(content);
                bodyOffset = info.getBodyOffset();
                headers = info.getHeaders();
            }
            String pretty = prettyJson(new String(content, bodyOffset, content.length - bodyOffset, charset));
            if (pretty == null) {
                return null;
            }
            return Utils.helpers.buildHttpMessage(headers, pretty.getBytes(charset));
        } catch (Exception e) {
            return null;
        }
    }
}
