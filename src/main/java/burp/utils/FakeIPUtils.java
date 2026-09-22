package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.bean.ConfigBean;
import burp.dao.ConfigDao;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** FakeIP 模块核心逻辑与配置状态：开启后对应用范围内工具的出站请求，
 *  将勾选的伪造头替换/追加为所选 IP（随机国内 IP / 127.0.0.1 / 自定义）。
 *  头列表与 IP 段移植自开源项目 burpFakeIP(TheKingOfDuck, MIT)。
 *  配置存 config 表(module=FakeIP);enabled 开关不持久化,重启默认关,避免静默改包。 */
public class FakeIPUtils {
    public static final String MODULE = "FakeIP";
    /** 伪造 IP 模式取值（存库用）。 */
    public static final String IP_MODE_RANDOM = "random";
    public static final String IP_MODE_LOCALHOST = "localhost";
    public static final String IP_MODE_CUSTOM = "custom";

    /** 应用范围候选工具（显示名 → Burp 工具标记），按界面展示顺序。 */
    public static final Map<String, Integer> SCOPE_TOOLS = createScopeTools();

    /** 常见可伪造客户端 IP 的请求头。 */
    public static final List<String> FAKE_IP_HEADERS = Collections.unmodifiableList(Arrays.asList(
            "X-Forwarded-For", "X-Forwarded", "Forwarded-For", "Forwarded", "X-Requested-With",
            "X-Forwarded-Proto", "X-Forwarded-Host", "X-remote-IP", "X-remote-addr", "True-Client-IP",
            "X-Client-IP", "Client-IP", "X-Real-IP", "Ali-CDN-Real-IP", "Cdn-Src-Ip", "Cdn-Real-Ip",
            "CF-Connecting-IP", "X-Cluster-Client-IP", "WL-Proxy-Client-IP", "Proxy-Client-IP",
            "Fastly-Client-Ip", "True-Client-Ip", "X-Originating-IP", "X-Host",
            "X-Custom-IP-Authorization", "X-Api-Version"));

    /** 随机国内 IP 段（int 起止，负数为高位段）。 */
    private static final int[][] IP_RANGES = {
            {607649792, 608174079}, {1038614528, 1039007743}, {1783627776, 1784676351},
            {2035023872, 2035154943}, {2078801920, 2079064063}, {-1950089216, -1948778497},
            {-1425539072, -1425014785}, {-1236271104, -1235419137}, {-770113536, -768606209},
            {-569376768, -564133889}};

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Set<String> DEFAULT_SCOPE = Collections.unmodifiableSet(
            new LinkedHashSet<>(Arrays.asList("proxy", "repeater")));
    private static final Set<String> DEFAULT_HEADERS = Collections.unmodifiableSet(
            new LinkedHashSet<>(Arrays.asList("X-Forwarded-For", "X-Real-IP")));

    private static volatile boolean fakeIpEnabled = false;
    /** 应用范围，存 SCOPE_TOOLS 的工具标记。 */
    private static volatile Set<Integer> scope = flagsOfNames(DEFAULT_SCOPE);
    private static volatile String ipMode = IP_MODE_RANDOM;
    private static volatile String customIp = "";
    private static volatile Set<String> selectedHeaders = DEFAULT_HEADERS;

    private static Map<String, Integer> createScopeTools() {
        Map<String, Integer> tools = new LinkedHashMap<>();
        tools.put("Proxy", IBurpExtenderCallbacks.TOOL_PROXY);
        tools.put("Repeater", IBurpExtenderCallbacks.TOOL_REPEATER);
        tools.put("Intruder", IBurpExtenderCallbacks.TOOL_INTRUDER);
        tools.put("Target", IBurpExtenderCallbacks.TOOL_TARGET);
        tools.put("Spider", IBurpExtenderCallbacks.TOOL_SPIDER);
        tools.put("Scanner", IBurpExtenderCallbacks.TOOL_SCANNER);
        tools.put("Extender", IBurpExtenderCallbacks.TOOL_EXTENDER);
        return Collections.unmodifiableMap(tools);
    }

    public static boolean isFakeIpEnabled() {
        return fakeIpEnabled;
    }

    public static void setFakeIpEnabled(boolean enabled) {
        fakeIpEnabled = enabled;
    }

    /** 应用范围（小写工具名集合，如 proxy/repeater），未知名字忽略。 */
    public static Set<String> getScopeNames() {
        return namesOfFlags(scope);
    }

    public static void setScopeNames(Set<String> names) {
        Set<Integer> flags = flagsOfNames(names);
        scope = flags.isEmpty() ? flagsOfNames(DEFAULT_SCOPE) : flags;
    }

    public static String getIpMode() {
        return ipMode;
    }

    public static void setIpMode(String mode) {
        if (IP_MODE_RANDOM.equals(mode) || IP_MODE_LOCALHOST.equals(mode) || IP_MODE_CUSTOM.equals(mode)) {
            ipMode = mode;
        }
    }

    public static String getCustomIp() {
        return customIp;
    }

    public static void setCustomIp(String ip) {
        customIp = ip == null ? "" : ip.trim();
    }

    /** 勾选的伪造头集合；只保留已知头（忽略大小写去重）。 */
    public static Set<String> getSelectedHeaders() {
        return selectedHeaders;
    }

    public static void setSelectedHeaders(Set<String> headers) {
        Set<String> picked = new LinkedHashSet<>();
        for (String known : FAKE_IP_HEADERS) {
            for (String want : headers) {
                if (want != null && known.equalsIgnoreCase(want.trim())) {
                    picked.add(known);
                    break;
                }
            }
        }
        selectedHeaders = Collections.unmodifiableSet(picked);
    }

    public static boolean isInScope(int toolFlag) {
        return scope.contains(toolFlag);
    }

    /** 启动时从 config 表恢复配置；enabled 不恢复（默认关）。 */
    public static void loadConfig() {
        String savedScope = ConfigDao.getConfig(MODULE, "scope").getValue();
        if (savedScope != null && !savedScope.trim().isEmpty()) {
            setScopeNames(new LinkedHashSet<>(Arrays.asList(savedScope.toLowerCase().split(","))));
        }
        String savedMode = ConfigDao.getConfig(MODULE, "ip_mode").getValue();
        if (savedMode != null && !savedMode.isEmpty()) {
            setIpMode(savedMode);
        }
        String savedCustomIp = ConfigDao.getConfig(MODULE, "custom_ip").getValue();
        if (savedCustomIp != null) {
            setCustomIp(savedCustomIp);
        }
        String savedHeaders = ConfigDao.getConfig(MODULE, "headers").getValue();
        if (savedHeaders != null && !savedHeaders.trim().isEmpty()) {
            setSelectedHeaders(new LinkedHashSet<>(Arrays.asList(savedHeaders.split(","))));
        }
    }

    /** 配置落库（config 表 upsert）；调用方负责挪出 EDT。 */
    public static void saveConfig() {
        ConfigDao.saveConfig(new ConfigBean(MODULE, "scope", join(getScopeNames())));
        ConfigDao.saveConfig(new ConfigBean(MODULE, "ip_mode", ipMode));
        ConfigDao.saveConfig(new ConfigBean(MODULE, "custom_ip", customIp));
        ConfigDao.saveConfig(new ConfigBean(MODULE, "headers", join(selectedHeaders)));
    }

    /** 按当前模式解析本次请求使用的 IP；自定义模式留空时退回随机 IP。 */
    public static String resolveIp() {
        if (IP_MODE_LOCALHOST.equals(ipMode)) {
            return "127.0.0.1";
        }
        if (IP_MODE_CUSTOM.equals(ipMode) && !customIp.isEmpty()) {
            return customIp;
        }
        return getRandomIp();
    }

    /** 对请求替换/追加全部勾选的伪造头，值统一为本次解析出的 IP。 */
    public static void applyFakeIp(IHttpRequestResponse message) {
        String ip = resolveIp();
        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(message);
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        for (String key : selectedHeaders) {
            removeHeader(headers, key);
            headers.add(key + ": " + ip);
        }
        message.setRequest(Utils.helpers.buildHttpMessage(headers, getBody(message, requestInfo)));
    }

    private static Set<Integer> flagsOfNames(Set<String> names) {
        Set<Integer> flags = new LinkedHashSet<>();
        if (names == null) {
            return flags;
        }
        for (Map.Entry<String, Integer> entry : SCOPE_TOOLS.entrySet()) {
            for (String name : names) {
                if (name != null && name.trim().equalsIgnoreCase(entry.getKey())) {
                    flags.add(entry.getValue());
                    break;
                }
            }
        }
        return flags;
    }

    private static Set<String> namesOfFlags(Set<Integer> flags) {
        Set<String> names = new LinkedHashSet<>();
        for (Map.Entry<String, Integer> entry : SCOPE_TOOLS.entrySet()) {
            if (flags.contains(entry.getValue())) {
                names.add(entry.getKey().toLowerCase());
            }
        }
        return names;
    }

    private static String join(Set<String> values) {
        return String.join(",", values);
    }

    /** 按名忽略大小写移除请求头。 */
    private static void removeHeader(List<String> headers, String key) {
        headers.removeIf(header -> {
            int idx = header.indexOf(':');
            return idx > 0 && header.substring(0, idx).trim().equalsIgnoreCase(key);
        });
    }

    private static byte[] getBody(IHttpRequestResponse message, IRequestInfo requestInfo) {
        byte[] request = message.getRequest();
        int offset = requestInfo.getBodyOffset();
        byte[] body = new byte[request.length - offset];
        System.arraycopy(request, offset, body, 0, body.length);
        return body;
    }

    /** 随机取一个国内 IP。 */
    public static String getRandomIp() {
        int[] range = IP_RANGES[RANDOM.nextInt(IP_RANGES.length)];
        return num2ip(range[0] + RANDOM.nextInt(range[1] - range[0]));
    }

    /** 整数转点分 IPv4（负数按无符号位型处理）。 */
    public static String num2ip(int ip) {
        return ((ip >> 24) & 0xff) + "." + ((ip >> 16) & 0xff) + "." + ((ip >> 8) & 0xff) + "." + (ip & 0xff);
    }
}
