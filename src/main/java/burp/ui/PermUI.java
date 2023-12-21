package burp.ui;

import burp.*;
import burp.bean.ConfigBean;
import burp.utils.Utils;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static burp.dao.ConfigDao.getConfig;
import static burp.dao.ConfigDao.saveConfig;
import static burp.utils.Utils.getSuffix;


public class PermUI implements UIHandler, IMessageEditorController, IHttpListener {
    private static final List<LogEntry> log = new ArrayList<>();
    private static final List<String> parameterList = new ArrayList<>();
    private static final List<String> urlHashList = new ArrayList<>();
    private static JTable permTable;
    private static boolean whiteDomain;
    private static boolean passiveScan;
    private JPanel panel;
    private JTabbedPane tabbedPane2;
    private JPanel originTabbedPane;
    private JPanel lowTabbedPane;
    private JPanel noTabbedPane;
    private JPanel permleftJpanel;
    private JCheckBox permPassiveCheckBox;
    private JCheckBox permWhiteDomainCheckBox;
    private JTextField permWhiteDomaintextField;
    private JButton permRefershButton;
    private JButton permClearButton;
    private JButton permSaveDomainButton;
    private JButton permSaveAuthButton;
    private JEditorPane permLowEditorPane1;
    private JEditorPane permNoEditorPane1;
    private JPanel permrightJpanel;
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor originarequest;
    private IMessageEditor originaresponse;
    private IMessageEditor lowerrequest;
    private IMessageEditor lowerresponse;
    private IMessageEditor norequest;
    private IMessageEditor noresponse;

    public static void Check(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();
        for (IParameter paraList : paraLists) {
            String paraName = paraList.getName();
            parameterList.add(paraName);
        }
        if (!checkUrlHash(method + url + parameterList.toString())) {
            return;
        }

        try {
            // 静态资源不检测
            List<String> suffix = getSuffix();
            if (!suffix.isEmpty()) {
                for (String s : suffix) {
                    if (url.endsWith(s) || url.contains(s)) {
                        return;
                    }
                }
            }

            if (whiteDomain) {
                ConfigBean configPermWhiteDomain = getConfig("perm", "permWhiteDomain");
                if (configPermWhiteDomain.getValue().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "请先填写白名单域名", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (!url.contains(configPermWhiteDomain.getValue())) {
                    return;
                }
            }

            // 原始请求
            List<String> originalheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
            byte[] postMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
            IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
            byte[] responseBody = originalRequestResponse.getResponse();
            String originallength = "";
            if (responseBody != null) {
                IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
                List<String> headers = originalReqResponse.getHeaders();
                for (String header : headers) {
                    if (header.contains("Content-Length")) {
                        originallength = header.split(":")[1].trim();
                        break;
                    }
                }
            }
            if (originallength.isEmpty()) {
                assert responseBody != null;
                originallength = String.valueOf(responseBody.length);
            }


            // 低权限请求
            List<String> lowheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            ConfigBean permLow = getConfig("perm", "permLowAuth");
            String lowAuthText = permLow.getValue();
            if (lowAuthText.contains("|XXXXX|")) {
                String[] lowAuths = lowAuthText.split("\\|XXXXX\\|");
                for (String lowAuth : lowAuths) {
                    String head = lowAuth.split(":")[0];
                    boolean headerFound = false;
                    for (int i = 0; i < lowheaders.size(); i++) {
                        String lowheader = lowheaders.get(i);
                        if (lowheader.contains(head)) {
                            lowheaders.set(i, lowAuth);
                            headerFound = true;
                            break;
                        }
                    }
                    if (!headerFound) {
                        lowheaders.add(lowAuth);
                    }
                }
            } else {
                String head = lowAuthText.split(":")[0];
                boolean headerFound = false;

                for (int i = 0; i < lowheaders.size(); i++) {
                    String lowheader = lowheaders.get(i);
                    if (lowheader.contains(head)) {
                        lowheaders.set(i, lowAuthText);
                        headerFound = true;
                        break;
                    }
                }

                if (!headerFound) {
                    lowheaders.add(lowAuthText);
                }
            }
            byte[] lowMessage = Utils.helpers.buildHttpMessage(lowheaders, body);
            IHttpRequestResponse lowRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), lowMessage);
            byte[] lowresponseBody = lowRequestResponse.getResponse();
            String lowlength = "";
            IResponseInfo lowReqResponse = Utils.helpers.analyzeResponse(lowresponseBody);
            List<String> lowReqResheaders = lowReqResponse.getHeaders();
            for (String header : lowReqResheaders) {
                if (header.contains("Content-Length")) {
                    lowlength = header.split(":")[1].trim();
                    break;
                }
            }
            if (lowlength.isEmpty()) {
                lowlength = String.valueOf(lowresponseBody.length);
            }


            // 无权限请求
            List<String> noheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            ConfigBean permNo = getConfig("perm", "permNoAuth");
            String noAuthText = permNo.getValue();
            if (noAuthText.contains("|XXXXX|")) {
                String[] noAuths = noAuthText.split("\\|XXXXX\\|");
                for (String noAuth : noAuths) {
                    noheaders.removeIf(noheader -> noheader.contains(noAuth));
                }
            } else {
                noheaders.removeIf(noheader -> noheader.contains(noAuthText));
            }
            byte[] noMessage = Utils.helpers.buildHttpMessage(noheaders, body);
            IHttpRequestResponse noRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), noMessage);
            byte[] noresponseBody = noRequestResponse.getResponse();
            String nolength = "";
            IResponseInfo noReqResponse = Utils.helpers.analyzeResponse(noresponseBody);
            List<String> noReqResheaders = noReqResponse.getHeaders();
            for (String header : noReqResheaders) {
                if (header.contains("Content-Length")) {
                    nolength = header.split(":")[1].trim();
                    break;
                }
            }
            if (nolength.isEmpty()) {
                nolength = String.valueOf(noresponseBody.length);
            }
            String isSuccess = "×";
            if (originallength.equals(lowlength) && lowlength.equals(nolength)) {
                isSuccess = "√";
            } else {
                isSuccess = "×";
            }

            add(method, url, originallength, lowlength, nolength, isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse);
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static boolean checkUrlHash(String url) {
        parameterList.clear();
        String md5 = DigestUtils.md5DigestAsHex(url.getBytes());
        if (urlHashList.contains(md5)) {
            return false;
        } else {
            urlHashList.add(md5);
            return true;
        }
    }

    private static void add(String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
        synchronized (log) {
            int id = log.size();
            log.add(new LogEntry(id, method, url, originalength, lowlength, nolength, isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse));
            permTable.updateUI();
        }
    }

    private void setupUI() {
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout(0, 0));
        permleftJpanel = new JPanel();
        permleftJpanel.setLayout(new BorderLayout(0, 0));
        panel.add(permleftJpanel, BorderLayout.CENTER);
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setDividerSize(2);
        splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane1.setResizeWeight(0.3);
        permleftJpanel.add(splitPane1, BorderLayout.CENTER);
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane1.setLeftComponent(scrollPane1);
        PermModel permModel = new PermModel();
        permTable = new URLTable(permModel);
        scrollPane1.setViewportView(permTable);
        tabbedPane2 = new JTabbedPane();
        splitPane1.setRightComponent(tabbedPane2);
        originTabbedPane = new JPanel();
        originTabbedPane.setLayout(new BorderLayout(0, 0));
        tabbedPane2.addTab("原始请求包", originTabbedPane);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setDividerSize(1);
        splitPane2.setResizeWeight(0.5);
        originarequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        originaresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        splitPane2.setLeftComponent(originarequest.getComponent());
        splitPane2.setRightComponent(originaresponse.getComponent());
        originTabbedPane.add(splitPane2, BorderLayout.CENTER);
        lowTabbedPane = new JPanel();
        lowTabbedPane.setLayout(new BorderLayout(0, 0));
        tabbedPane2.addTab("低权限请求包", lowTabbedPane);
        final JSplitPane splitPane3 = new JSplitPane();
        splitPane3.setDividerSize(1);
        splitPane3.setResizeWeight(0.5);
        lowerrequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        lowerresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        splitPane3.setLeftComponent(lowerrequest.getComponent());
        splitPane3.setRightComponent(lowerresponse.getComponent());
        lowTabbedPane.add(splitPane3, BorderLayout.CENTER);
        noTabbedPane = new JPanel();
        noTabbedPane.setLayout(new BorderLayout(0, 0));
        tabbedPane2.addTab("无权限请求包", noTabbedPane);
        final JSplitPane splitPane4 = new JSplitPane();
        splitPane4.setDividerSize(1);
        splitPane4.setResizeWeight(0.5);
        norequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        noresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        splitPane4.setLeftComponent(norequest.getComponent());
        splitPane4.setRightComponent(noresponse.getComponent());
        noTabbedPane.add(splitPane4, BorderLayout.CENTER);
        permrightJpanel = new JPanel();
        permrightJpanel.setLayout(new BorderLayout(0, 0));
        panel.add(permrightJpanel, BorderLayout.EAST);
        final JSplitPane splitPane5 = new JSplitPane();
        splitPane5.setDividerSize(0);
        splitPane5.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane5.setResizeWeight(0.3);
        permrightJpanel.add(splitPane5, BorderLayout.CENTER);
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(5, 2, new Insets(0, 0, 0, 0), -1, -1));
        splitPane5.setLeftComponent(panel2);
        permPassiveCheckBox = new JCheckBox();
        permPassiveCheckBox.setText("被动扫描");
        panel2.add(permPassiveCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        permWhiteDomainCheckBox = new JCheckBox();
        permWhiteDomainCheckBox.setText("白名单域名");
        panel2.add(permWhiteDomainCheckBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("白名单域名");
        panel2.add(label1, new GridConstraints(1, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        permWhiteDomaintextField = new JTextField();
        panel2.add(permWhiteDomaintextField, new GridConstraints(2, 0, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        permRefershButton = new JButton();
        permRefershButton.setText("刷新");
        panel2.add(permRefershButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        permClearButton = new JButton();
        permClearButton.setText("清空数据");
        panel2.add(permClearButton, new GridConstraints(4, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        permSaveDomainButton = new JButton();
        permSaveDomainButton.setText("保存白名单");
        panel2.add(permSaveDomainButton, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        permSaveAuthButton = new JButton();
        permSaveAuthButton.setText("保存认证数据");
        panel2.add(permSaveAuthButton, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JSplitPane splitPane6 = new JSplitPane();
        splitPane6.setDividerSize(0);
        splitPane6.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane6.setResizeWeight(0.5);
        splitPane5.setRightComponent(splitPane6);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new BorderLayout(0, 0));
        splitPane6.setLeftComponent(panel3);
        final JLabel label2 = new JLabel();
        label2.setText("低权限认证请求头信息");
        panel3.add(label2, BorderLayout.NORTH);
        permLowEditorPane1 = new JEditorPane();
        panel3.add(permLowEditorPane1, BorderLayout.CENTER);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new BorderLayout(0, 0));
        splitPane6.setRightComponent(panel4);
        final JLabel label3 = new JLabel();
        label3.setText("未授权请求头(输入请求头即可)");
        panel4.add(label3, BorderLayout.NORTH);
        permNoEditorPane1 = new JEditorPane();
        panel4.add(permNoEditorPane1, BorderLayout.CENTER);
    }

    private void setupData() {


        ConfigBean configPassiveScan = getConfig("perm", "permPassiveScanBox");
        if (configPassiveScan.getValue().equals("true")) {
            permPassiveCheckBox.setSelected(true);
            passiveScan = true;
        } else {
            permPassiveCheckBox.setSelected(false);
            passiveScan = false;
        }
        ConfigBean configWhiteDomain = getConfig("perm", "permWhiteDomain");
        permWhiteDomaintextField.setText(configWhiteDomain.getValue());
        ConfigBean configLowAuth = getConfig("perm", "permLowAuth");
        if (configLowAuth.getValue().contains("|XXXXX|")) {
            String[] lowAuths = configLowAuth.getValue().split("\\|XXXXX\\|");
            StringBuilder lowAuthText = new StringBuilder();
            for (String lowAuth : lowAuths) {
                lowAuthText.append(lowAuth).append("\n");
            }
            permLowEditorPane1.setText(lowAuthText.toString());
        } else {
            permLowEditorPane1.setText(configLowAuth.getValue());
        }
        ConfigBean configNoAuth = getConfig("perm", "permNoAuth");
        if (configNoAuth.getValue().contains("|XXXXX|")) {
            String[] noAuths = configNoAuth.getValue().split("\\|XXXXX\\|");
            StringBuilder noAuthText = new StringBuilder();
            for (String noAuth : noAuths) {
                noAuthText.append(noAuth).append("\n");
            }
            permNoEditorPane1.setText(noAuthText.toString());
        } else {
            permNoEditorPane1.setText(configNoAuth.getValue());
        }
        ConfigBean configWhiteDomainCheckBox = getConfig("perm", "permWhiteDomainCheckBox");
        if (configWhiteDomainCheckBox.getValue().equals("true")) {
            permWhiteDomainCheckBox.setSelected(true);
            whiteDomain = true;
        } else {
            permWhiteDomainCheckBox.setSelected(false);
            whiteDomain = false;
        }

        permPassiveCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (permPassiveCheckBox.isSelected()) {
                    passiveScan = true;
                    ConfigBean configBean = new ConfigBean("perm", "permPassiveScanBox", "true");
                    saveConfig(configBean);
                } else {
                    passiveScan = false;
                    ConfigBean configBean = new ConfigBean("perm", "permPassiveScanBox", "false");
                    saveConfig(configBean);
                }
            }
        });
        permRefershButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                permTable.updateUI();
            }
        });
        permClearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log.clear();
                originarequest.setMessage(new byte[0], true);
                originaresponse.setMessage(new byte[0], false);
                lowerrequest.setMessage(new byte[0], false);
                lowerresponse.setMessage(new byte[0], false);
                norequest.setMessage(new byte[0], false);
                noresponse.setMessage(new byte[0], false);
                permTable.updateUI();
            }
        });
        permSaveAuthButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String low = permLowEditorPane1.getText();
                String no = permNoEditorPane1.getText();
                if (low.isEmpty() || no.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "认证数据不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (low.contains("\n")) {
                    low = low.replaceAll("\n", "|XXXXX|");
                }
                if (no.contains("\n")) {
                    no = no.replaceAll("\n", "|XXXXX|");
                }
                ConfigBean configLowAuth = new ConfigBean("perm", "permLowAuth", low);
                saveConfig(configLowAuth);
                ConfigBean configNoAuth = new ConfigBean("perm", "permNoAuth", no);
                saveConfig(configNoAuth);
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        permSaveDomainButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String domain = permWhiteDomaintextField.getText();
                if (domain.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "域名不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                ConfigBean configWhiteDomain = new ConfigBean("perm", "permWhiteDomain", domain);
                saveConfig(configWhiteDomain);

                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        permWhiteDomainCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (permWhiteDomainCheckBox.isSelected()) {
                    whiteDomain = true;
                    ConfigBean configBean = new ConfigBean("perm", "permWhiteDomainCheckBox", "true");
                    saveConfig(configBean);
                } else {
                    whiteDomain = false;
                    ConfigBean configBean = new ConfigBean("perm", "permWhiteDomainCheckBox", "false");
                    saveConfig(configBean);
                }
            }
        });

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {

        if (passiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (log) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse});
                    }
                });
                thread.start();
            }
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
        return "未授权访问";
    }

    static class PermModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return log.size();
        }

        @Override
        public int getColumnCount() {
            return 7;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return log.get(rowIndex).id;
                case 1:
                    return log.get(rowIndex).method;
                case 2:
                    return log.get(rowIndex).url;
                case 3:
                    return log.get(rowIndex).originalength;
                case 4:
                    return log.get(rowIndex).lowlength;
                case 5:
                    return log.get(rowIndex).nolength;
                case 6:
                    return log.get(rowIndex).isSuccess;
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
                    return "originalength";
                case 4:
                    return "lowlength";
                case 5:
                    return "nolength";
                case 6:
                    return "isSuccess";
                default:
                    return null;
            }
        }
    }

    private static class LogEntry {
        final int id;
        final String method;
        final String url;
        final String originalength;
        final String lowlength;
        final String nolength;
        final String isSuccess;
        IHttpRequestResponse requestResponse;
        IHttpRequestResponse lowRequestResponse;
        IHttpRequestResponse noRequestResponse;

        public LogEntry(int id, String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse requestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.originalength = originalength;
            this.lowlength = lowlength;
            this.nolength = nolength;
            this.isSuccess = isSuccess;
            this.requestResponse = requestResponse;
            this.lowRequestResponse = lowRequestResponse;
            this.noRequestResponse = noRequestResponse;
        }
    }

    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            LogEntry logEntry = log.get(row);
            originarequest.setMessage(logEntry.requestResponse.getRequest(), true);
            originaresponse.setMessage(logEntry.requestResponse.getResponse(), false);
            if (logEntry.lowRequestResponse == null || logEntry.noRequestResponse == null) {
                lowerrequest.setMessage(null, false);
                lowerresponse.setMessage(null, false);
                norequest.setMessage(null, false);
                noresponse.setMessage(null, false);
                return;
            }
            lowerrequest.setMessage(logEntry.lowRequestResponse.getRequest(), true);
            lowerresponse.setMessage(logEntry.lowRequestResponse.getResponse(), false);
            norequest.setMessage(logEntry.noRequestResponse.getRequest(), true);
            noresponse.setMessage(logEntry.noRequestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

}
