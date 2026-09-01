package burp.ui;

import burp.*;
import burp.bean.AuthBean;
import burp.utils.HostThrottle;
import burp.utils.I18nUtils;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 目录穿越/鉴权绕过（BypassAuth）检测面板：对 GET/POST 请求生成前缀/后缀路径变异
 * （;/.、%2e、..;/ 等）与伪造 IP 头、Accept 头替换请求，按响应状态/长度记录结果。
 * 检测在静态 lock 内串行执行，目标主机经 HostThrottle 限速；
 * 结果入静态有界 ScanResultsStore；不支持被动扫描（doPassiveScan 为空实现）。
 */
public class AuthUI extends AbstractScanUI {
    private JButton btnClear;
    private JTextField ipInputField;
    private JButton saveBtn;
    private JTabbedPane requestTabPane;
    private JTabbedPane responseTabPane;

    /** 由 EDT（保存按钮）写、扫描线程（prefix/suffix）读，需 volatile 保证可见性。 */
    private static volatile String LOCAL_IP = "127.0.0.1";
    // 主动检测串行锁
    private static final Lock lock = new ReentrantLock();
    // 当前面板实例：静态 Check 入口经此定位到实例
    private static volatile AuthUI instance;
    /** 结果列表容量上限，超限淘汰最旧条目，防长时间会话内存增长。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    private static final ScanResultsStore<AuthEntry> authlog = new ScanResultsStore<>(MAX_LOG_ENTRIES, () -> {
        AuthUI ui = instance;
        if (ui != null) {
            ui.refreshTableModel(ui.resultTable);
        }
    });

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        AuthUI ui = instance;
        if (ui != null) {
            ui.currentlyDisplayedItem = item;
        }
    }

    static List<AuthEntry> getAuthlog() {
        return authlog.list();
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        resultTable = new AuthTable(new AuthModel(), requestEditor, responseEditor);
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        btnClear = new JButton(I18nUtils.get("auth.button.clear"));
        topPanel.add(btnClear);

        topPanel.add(new JLabel(I18nUtils.get("auth.label.ip")));
        ipInputField = new JTextField("127.0.0.1");
        topPanel.add(ipInputField);

        saveBtn = new JButton(I18nUtils.get("auth.button.save"));
        topPanel.add(saveBtn);

        panel.add(topPanel, BorderLayout.NORTH);

        getResultTable().setAutoCreateRowSorter(true);

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setTopComponent(wrapResultsTable(getResultTable()));
        mainSplitPane.setBottomComponent(buildEditorSplit());
        applyWeights(mainSplitPane, WEIGHT_TABLE_EDITOR);

        panel.add(mainSplitPane, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        btnClear.addActionListener(e -> {
            // store.clear 内部加锁，与扫描线程的 add 互斥
            authlog.clear();
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
            UrlCacheUtil.resetCache("auth");
            refreshTableModel(getResultTable());
        });

        saveBtn.addActionListener(e -> {
            if (!ipInputField.getText().equals(LOCAL_IP)) {
                LOCAL_IP = ipInputField.getText();
            } else {
                LOCAL_IP = "127.0.0.1";
            }
        });
    }

    @Override
    public String getTabName() {
        return "BypassAuth";
    }

    @Override
    protected String getScanName() {
        return "Auth";
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        // AuthUI doesn't support passive scanning
    }

    /** Auth 主动检测核心（ScanTaskExecutor 池线程，经右键菜单调用）：
     *  依次执行前缀/后缀路径变异、伪造 IP 头、Accept 头替换三类探测。 */
    public static void Check(IHttpRequestResponse[] requestResponses) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = requestResponses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String method = analyzeRequest.getMethod();
            String path = analyzeRequest.getUrl().getPath();
            String request = Utils.helpers.bytesToString(baseRequestResponse.getRequest());
            URL rdurlURL = analyzeRequest.getUrl();
            String url = analyzeRequest.getUrl().toString();
            byte[] byte_Request = baseRequestResponse.getRequest();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, analyzeRequest.getBodyOffset(), len);

            if (Utils.isUrlBlackListSuffix(url)) {
                return;
            }

            // 复用方法入口处的解析结果，避免重复 analyzeRequest
            List<String> headers = analyzeRequest.getHeaders();
            String urlWithoutQuery = "";
            try {
                URL url1 = new URL(url);
                String protocol = url1.getProtocol();
                String host = url1.getHost();
                int port = url1.getPort();
                urlWithoutQuery = protocol + "://" + host + ":" + port;
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }

            List<AuthBean> authRequests = new ArrayList<>();
            authRequests.addAll(prefix(method, path));
            authRequests.addAll(suffix(method, path));

            if (Objects.equals(method, "GET") || Objects.equals(method, "POST")) {
                for (AuthBean value : authRequests) {
                    // 字面量替换第一次出现的 path：replaceFirst 第一参数是正则，
                    // 路径中的 ? . + 等元字符会导致替换错位或失配
                    String new_request = Utils.replaceFirstLiteral(request, path, value.getPath());
                    HostThrottle.throttle(serviceKey(baseRequestResponse));
                    IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                    if (response == null || response.getResponse() == null) {
                        Utils.stderr.println("Auth scan skipped: target returned no response");
                        continue;
                    }
                    String requrl = urlWithoutQuery + value.getPath();
                    String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
                    String length = String.valueOf(response.getResponse().length);
                    add(method, requrl, statusCode, length, response);
                }
                List<AuthBean> testHeaders = forgeHeaders(method, url);
                for (AuthBean header : testHeaders) {
                    headers.add(header.getHeaders());
                }
                byte[] message = Utils.helpers.buildHttpMessage(headers, body);
                IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
                if (response != null && response.getResponse() != null) {
                    String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
                    String length = String.valueOf(response.getResponse().length);
                    add(method, url, statusCode, length, response);
                }
                for (AuthBean header : testHeaders) {
                    headers.remove(header.getHeaders());
                }
                changeAccept(headers, body, method, url, baseRequestResponse);
            }
        } finally {
            lock.unlock();
        }
    }

    /** 追加一条探测结果到有界 store（自动刷新表格）。 */
    private static void add(String method, String url, String statuscode, String length, IHttpRequestResponse baseRequestResponse) {
        authlog.add(id -> new AuthEntry(id, method, url, statuscode, length, baseRequestResponse));
    }

    /** 生成后缀路径变异 payload（%2e/、/.、..;/、%20/ 等）；双斜杠开头先归一。 */
    public static List<AuthBean> suffix(String method, String path) {
        if (path.startsWith("//")) {
            path = "/" + path.substring(2).replaceAll("/+", "/");
        }
        List<AuthBean> authRequests = new ArrayList<>();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
            List<String> payloads = Arrays.asList(path + "%2e/", path + "/.", "./" + path + "/./", path + "%20/",
                    "/%20" + path + "%20/", path + "..;/", path + "?", path + "??", "/" + path + "//",
                    path + "/", path + "/.randomstring");
            for (String payload : payloads) {
                if ("GET".equals(method)) {
                    authRequests.add(new AuthBean("GET", payload, ""));
                } else if ("POST".equals(method)) {
                    authRequests.add(new AuthBean("POST", payload, ""));
                }
            }
        } else {
            List<String> payloads = Arrays.asList(path + "/%2e", path + "/%20", path + "%0d%0a", path + ".json", path + "/.randomstring");
            for (String payload : payloads) {
                if ("GET".equals(method)) {
                    authRequests.add(new AuthBean("GET", payload, ""));
                } else if ("POST".equals(method)) {
                    authRequests.add(new AuthBean("POST", payload, ""));
                }
            }
        }
        return authRequests;
    }

    /** 生成前缀路径变异 payload（;/、.;/、images/..;/ 等注入到路径各段之间）。 */
    public static List<AuthBean> prefix(String method, String path) {
        if (path.startsWith("//")) {
            path = "/" + path.substring(2).replaceAll("/+", "/");
        }
        List<AuthBean> authRequests = new ArrayList<>();
        String[] prefix = {";/", ".;/", "images/..;/", ";a/", "%23/../", "..;/..;/"};
        for (String s : prefix) {
            String[] pathParts = path.split("/");
            for (int i = 1; i < pathParts.length; i++) {
                String[] subPathParts = Arrays.copyOfRange(pathParts, i, pathParts.length);
                String[] prePathParts = Arrays.copyOfRange(pathParts, 1, i);
                String basePath = prePathParts.length > 0
                        ? "/" + String.join("/", prePathParts) + "/" + s + String.join("/", subPathParts)
                        : "/" + s + String.join("/", subPathParts);
                if ("GET".equals(method)) {
                    authRequests.add(new AuthBean("GET", basePath, ""));
                } else if ("POST".equals(method)) {
                    authRequests.add(new AuthBean("POST", basePath, ""));
                }
            }
        }
        return authRequests;
    }

    /** 生成伪造 IP 头探测（X-Forwarded-For 等 4 个头，IP 取 LOCAL_IP）。 */
    public static List<AuthBean> forgeHeaders(String method, String url) {
        List<AuthBean> authRequests = new ArrayList<>();
        List<String> payloads = Arrays.asList(
                "X-Forwarded-For: %s",
                "X-Originating-IP: %s",
                "X-Remote-IP: %s",
                "X-Remote-Addr: %s"
        );
        payloads.replaceAll(s -> String.format(s, LOCAL_IP));

        for (String payload : payloads) {
            if ("GET".equals(method)) {
                authRequests.add(new AuthBean("GET", "", payload));
            } else if ("POST".equals(method)) {
                authRequests.add(new AuthBean("POST", "", payload));
            }
        }
        return authRequests;
    }

    /** Accept 头替换探测：移除原 Accept 后加标准 JSON Accept 重放请求（池线程内调用）。 */
    public static void changeAccept(List<String> headers, byte[] body, String method, String url, IHttpRequestResponse baseRequestResponse) {
        headers.removeIf(header -> header.startsWith("Accept:"));
        // 修复：原值 "text/javascript, /; q=0.01" 丢失了 */*（历史转义问题），是非法 Accept 头
        headers.add("Accept: application/json, text/javascript, */*; q=0.01");
        HostThrottle.throttle(serviceKey(baseRequestResponse));
        byte[] message = Utils.helpers.buildHttpMessage(headers, body);
        IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
        if (response == null || response.getResponse() == null) {
            Utils.stderr.println("Auth scan skipped: target returned no response");
            return;
        }
        String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
        String length = String.valueOf(response.getResponse().length);
        add(method, url, statusCode, length, response);
    }

    private static String serviceKey(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }
}
