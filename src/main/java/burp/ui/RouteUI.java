package burp.ui;

import burp.*;
import burp.bean.RouteBean;
import burp.dao.RouteDao;
import burp.utils.CustomScanIssue;
import burp.utils.ExpressionUtils;
import burp.utils.Utils;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.dao.RouteDao.*;
import static burp.utils.Utils.getSuffix;

/**
 * @Author Xm17
 * @Date 2024-06-22 22:02
 */
public class RouteUI implements UIHandler, IMessageEditorController, IHttpListener {
    private JPanel panel; // 主面板
    private static IHttpRequestResponse currentlyDisplayedItem; // 当前显示的请求
    private IMessageEditor HRequestTextEditor; // 请求
    private IMessageEditor HResponseTextEditor; // 响应
    private JTabbedPane tabbedPanereq; // 请求tab
    private JTabbedPane tabbedPaneresp; // 响应tab
    private static RouteIssusTable issusTable; // 问题表格
    private RouteTable ruleTable; // 规则表格
    private static final List<RouteIssusEntry> issuslog = new ArrayList<>();  // urldata
    private static final List<RouteEntry> routelog = new ArrayList<>();  // routelog
    private JScrollPane issustablescrollpane; // 问题表格滚动面板
    private JScrollPane ruleTableScrollPane; // 规则表格滚动面板
    private JButton refreshButton; // 刷新按钮
    private JButton clearButton; // 清空按钮
    private JCheckBox passiveCheckBox; // 被动扫描选择框
    private JTextField nameTextField; // name输入框
    private JTextField pathTextField; // path输入框
    private JTextField expressTextField; // express输入框
    private JButton addButton; // 添加按钮
    private JButton deleteButton; // 删除按钮
    private JButton enableButton; // 开启按钮
    private boolean passiveScan; // 是否被动扫描
    private static final List<String> parameterList = new ArrayList<>(); // 参数列表
    private static final List<String> urlHashList = new ArrayList<>(); // urlHash列表


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && passiveScan) {
            synchronized (issuslog) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse},false);
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
    // 初始化数据
    private void setupData() {
        //ruleTable
        List<RouteBean> routeLists = getRouteLists();
        for (int i = 0; i < routeLists.size(); i++) {
            RouteBean routeBean = routeLists.get(i);
            routelog.add(new RouteEntry(i, routeBean.getEnable(), routeBean.getName(), routeBean.getPath(), routeBean.getExpress()));
        }
        // 刷新
        refreshButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                issusTable.updateUI();
                routelog.clear();
                List<RouteBean> routeLists = getRouteLists();
                for (int i = 0; i < routeLists.size(); i++) {
                    RouteBean routeBean = routeLists.get(i);
                    routelog.add(new RouteEntry(i, routeBean.getEnable(), routeBean.getName(), routeBean.getPath(), routeBean.getExpress()));
                }
                ruleTable.updateUI();
            }
        });
        // 清空
        clearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                issuslog.clear();
                issusTable.updateUI();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
            }
        });
        // 被动扫描
        passiveCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (passiveCheckBox.isSelected()) {
                    passiveScan = true;
                } else {
                    passiveScan = false;
                }
            }
        });
        // 添加规则
        addButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String name = nameTextField.getText();
                String path = pathTextField.getText();
                String express = expressTextField.getText();
                RouteBean routeBean = new RouteBean();
                routeBean.setEnable(1);
                routeBean.setName(name);
                routeBean.setPath(path);
                routeBean.setExpress(express);
                // 添加到数据库
                addRoute(routeBean);
                routelog.clear();
                List<RouteBean> routeLists = getRouteLists();
                for (int i = 0; i < routeLists.size(); i++) {
                    RouteBean routeBean1 = routeLists.get(i);
                    routelog.add(new RouteEntry(i, routeBean1.getEnable(), routeBean1.getName(), routeBean1.getPath(), routeBean1.getExpress()));
                }
                ruleTable.updateUI();
            }
        });
        // 删除选中
        deleteButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = ruleTable.getSelectedRow();
                if (selectedRow == -1) {
                    return;
                }
                RouteEntry routeEntry = routelog.get(selectedRow);
                RouteBean routeBean = new RouteBean();
                routeBean.setName(routeEntry.name);
                routeBean.setPath(routeEntry.path);
                routeBean.setExpress(routeEntry.express);
                deleteRoute(routeBean);
                routelog.clear();
                List<RouteBean> routeLists = getRouteLists();
                for (int i = 0; i < routeLists.size(); i++) {
                    RouteBean routeBean1 = routeLists.get(i);
                    routelog.add(new RouteEntry(i, routeBean1.getEnable(), routeBean1.getName(), routeBean1.getPath(), routeBean1.getExpress()));
                }
                ruleTable.updateUI();
            }
        });
        // 开启选中
        enableButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = ruleTable.getSelectedRow();
                if (selectedRow == -1) {
                    return;
                }
                RouteBean routeBean = new RouteBean();
                RouteEntry routeEntry = routelog.get(selectedRow);
                if (routeEntry.enable == 1){
                    routeBean.setEnable(0);
                }else if (routeEntry.enable == 0){
                    routeBean.setEnable(1);
                }
                routeBean.setName(routeEntry.name);
                routeBean.setPath(routeEntry.path);
                routeBean.setExpress(routeEntry.express);
                updateRouteEnable(routeBean);
                routelog.clear();
                List<RouteBean> routeLists = getRouteLists();
                for (int i = 0; i < routeLists.size(); i++) {
                    RouteBean routeBean1 = routeLists.get(i);
                    routelog.add(new RouteEntry(i, routeBean1.getEnable(), routeBean1.getName(), routeBean1.getPath(), routeBean1.getExpress()));
                }
                ruleTable.updateUI();
            }
        });

    }

    // 初始化ui
    private void setupUI() {
        // 注册消息监听
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel(new BorderLayout());

        // 添加一个JPanel 采用flowLayout布局
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        // 添加一个刷新按钮
        refreshButton = new JButton("refersh");
        topPanel.add(refreshButton);
        // 添加一个清空按钮
        clearButton = new JButton("clear");
        topPanel.add(clearButton);
        // 添加一个被动扫描选择框
        passiveCheckBox = new JCheckBox("passive");
        topPanel.add(passiveCheckBox);
        // 添加一个分割符号
        // 添加一个提示的的Jlabel
        JLabel tipsLabel = new JLabel("自定义规则添加: ");
        topPanel.add(tipsLabel);
        // 添加一个name的Jlabel
        JLabel nameLabel = new JLabel("name:");
        topPanel.add(nameLabel);
        // 添加一个name的输入框
        nameTextField = new JTextField(10);
        topPanel.add(nameTextField);
        // 添加一个path的Jlabel
        JLabel pathLabel = new JLabel("path:");
        topPanel.add(pathLabel);
        // 添加一个path的输入框
        pathTextField = new JTextField(10);
        topPanel.add(pathTextField);
        // 添加一个Express的Jlabel
        JLabel expressLabel = new JLabel("express:");
        topPanel.add(expressLabel);
        // 添加一个express的输入框
        expressTextField = new JTextField(10);
        topPanel.add(expressTextField);
        // 添加一个添加按钮
        addButton = new JButton("添加规则");
        topPanel.add(addButton);
        // 添加一个删除按钮
        deleteButton = new JButton("删除选中规则");
        topPanel.add(deleteButton);
        // 添加一个开启选中规则按钮
        enableButton = new JButton("开启/关闭选中规则");
        topPanel.add(enableButton);

        // 添加一个上下对称分割的面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);

        // 上面的面板左右对称分割
        JSplitPane topSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        topSplitPane.setResizeWeight(0.5);
        topSplitPane.setDividerLocation(0.5);
        // 添加RouteIssusTable
        issustablescrollpane = new JScrollPane();
        issusTable = new RouteIssusTable(new RouteIssusModel());
        issustablescrollpane.setViewportView(issusTable);
        topSplitPane.setLeftComponent(issustablescrollpane);

        // 添加RouteTable
        ruleTableScrollPane = new JScrollPane();
        ruleTable = new RouteTable(new RouteModel());
        ruleTableScrollPane.setViewportView(ruleTable);
        topSplitPane.setRightComponent(ruleTableScrollPane);



        // 下面的面板左右对称分割
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplitPane.setResizeWeight(0.5);
        bottomSplitPane.setDividerLocation(0.5);

        HRequestTextEditor = Utils.callbacks.createMessageEditor(this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(this, false);
        tabbedPanereq = new JTabbedPane();
        tabbedPanereq.addTab("request", HRequestTextEditor.getComponent());
        tabbedPaneresp = new JTabbedPane();
        tabbedPaneresp.addTab("response", HResponseTextEditor.getComponent());
        bottomSplitPane.setLeftComponent(tabbedPanereq);
        bottomSplitPane.setRightComponent(tabbedPaneresp);


        splitPane.setTopComponent(topSplitPane);
        splitPane.setBottomComponent(bottomSplitPane);


        // 添加工具到顶部
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {

        return panel;
    }

    @Override
    public String getTabName() {
        return "RouteScan";
    }

    // 核心方法
    public static void Check(IHttpRequestResponse[] responses,boolean isSend) {
        IHttpRequestResponse iHttpRequestResponse = responses[0];
        // 考虑iHttpRequestResponse.getResponse()为null
        if (iHttpRequestResponse.getResponse() == null) {
            return;
        }
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(iHttpRequestResponse);
        URL rdurlURL = analyzeRequest.getUrl();
        String url = analyzeRequest.getUrl().toString();
        String method = analyzeRequest.getMethod();
        String request = Utils.helpers.bytesToString(iHttpRequestResponse.getRequest());
        String requestx = "";
        String path = analyzeRequest.getUrl().getPath();

        // 如果method不是get或者post方式直接返回
        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }

        // url 中为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s)) {
                return;
            }
        }
        // 对url进行hash去重
        String rdurl = Utils.getUrlWithoutFilename(rdurlURL);
        if (!isSend){
            if (!checkUrlHash(method + rdurl)) {
                return;
            }
        }
        // 获取payload
        List<RouteBean> routeList = getRouteLists();

        for (RouteBean routeBean : routeList) {
            // 如果没有开启，直接跳过
            if (routeBean.getEnable() != 1){
                continue;
            }
            // 定义正则表达式，匹配 ? 及其后面的内容
            String regex = "\\?[^\\s]*";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(request);

            // 删除请求数据包中的参数部分
            if (matcher.find()) {
                requestx = request.replace(matcher.group(), "");
            }
            List<String> reqLists = append(path, routeBean.getPath());
            for (String reqList : reqLists) {
                if (Objects.equals(method, "GET")) {
                    String new_request = requestx.replaceFirst(path, reqList);
                    IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                    ExpressionUtils expressionUtils = new ExpressionUtils(response);
                    boolean process = expressionUtils.process(routeBean.getExpress());
                    if (process) {
                        addIssus(routeBean.getName(),expressionUtils.getUrl(),  String.valueOf(expressionUtils.getCode()), response);
                        IScanIssue issues = null;
                        try {
                            issues = new CustomScanIssue(iHttpRequestResponse.getHttpService(), new URL(expressionUtils.getUrl()), new IHttpRequestResponse[]{response},
                                    "Directory leakage", "A sensitive directory leak vulnerability was discovered.",
                                    "High", "Certain");
                            Utils.callbacks.addScanIssue(issues);
                        } catch (MalformedURLException e) {
                            throw new RuntimeException(e);
                        }
                    }
                } else if (Objects.equals(method, "POST")) {
                    // 删除post数据中的body部分
                    String request_data = request.split("\r\n\r\n")[0]+"\r\n\r\n";
                    String new_request = request_data.replaceFirst(path, reqList);
                    IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                    ExpressionUtils expressionUtils = new ExpressionUtils(response);
                    boolean process = expressionUtils.process(routeBean.getExpress());
                    if (process) {
                        addIssus(routeBean.getName(),expressionUtils.getUrl(), String.valueOf(expressionUtils.getCode()), response);
                        IScanIssue issues = null;
                        try {
                            issues = new CustomScanIssue(iHttpRequestResponse.getHttpService(), new URL(expressionUtils.getUrl()), new IHttpRequestResponse[]{response},
                                    "Directory leakage", "A sensitive directory leak vulnerability was discovered.",
                                    "High", "Certain");
                            Utils.callbacks.addScanIssue(issues);
                        } catch (MalformedURLException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }

        }
    }

    // 数据去重
    private static boolean checkUrlHash(String data) {
        String md5 = DigestUtils.md5DigestAsHex(data.getBytes());
        if (urlHashList.contains(md5)) {
            return false;
        } else {
            urlHashList.add(md5);
            return true;
        }
    }

    // 追加路径
    public static List<String> append(String basePath, String stringToAppend) {
        List<String> result = new ArrayList<>();
        String[] paths = basePath.split("/");
        StringBuilder currentPath = new StringBuilder();

        for (int i = 0; i < paths.length; i++) {
            String path = paths[i];
            if (!path.isEmpty()) {
                if (i == 0) {
                    currentPath.append(path);
                } else {
                    currentPath.append("/").append(path);
                }
                result.add(currentPath.toString() + stringToAppend);
            }
        }

        if (!basePath.endsWith("/")) {
            result.remove(result.size() - 1);
        }
        result.add(stringToAppend);
        return result;
    }

    public static void addIssus(String name, String url, String Status, IHttpRequestResponse requestResponse) {
        synchronized (issuslog) {
            // todo 去重
            issuslog.add(new RouteIssusEntry(issuslog.size(), name, url, Status, requestResponse));
            issusTable.updateUI();
        }
    }

    // RouteIssusModel模型
    static class RouteIssusModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return issuslog.size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RouteIssusEntry logEntry = issuslog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.issueName;
                case 2:
                    return logEntry.url;
                case 3:
                    return logEntry.status;
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
                    return "Issus name";
                case 2:
                    return "url";
                case 3:
                    return "status";
                default:
                    return "";
            }

        }

    }
    // RouteIssus实体
    private static class RouteIssusEntry {
        final int id;
        final String issueName;
        final String url;
        final String status;
        final IHttpRequestResponse requestResponse;

        public RouteIssusEntry(int id, String issueName, String url, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.issueName = issueName;
            this.url = url;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }
    // RouteIssusTable表格
    private class RouteIssusTable extends JTable {
        public RouteIssusTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(1).setMinWidth(100);
            columnModel.getColumn(1).setMaxWidth(150);
            columnModel.getColumn(3).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            RouteIssusEntry issusEntry = issuslog.get(row);
            HRequestTextEditor.setMessage(issusEntry.requestResponse.getRequest(), true);
            if (issusEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(issusEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = issusEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    // 路由规则实体
    public static class RouteEntry {
        final int id;
        int enable;
        final String name;
        final String path;
        final String express;

        public RouteEntry(int id, int enable, String name, String path, String express) {
            this.id = id;
            this.enable = enable;
            this.name = name;
            this.path = path;
            this.express = express;
        }
    }
    // 路由表格模型
    static class RouteModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return routelog.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RouteEntry logEntry = routelog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.enable == 1 ? "开启" : "关闭";
                case 2:
                    return logEntry.name;
                case 3:
                    return logEntry.path;
                case 4:
                    return logEntry.express;
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
                    return "enable";
                case 2:
                    return "name";
                case 3:
                    return "path";
                case 4:
                    return "express";
                default:
                    return "";
            }

        }

    }
    // 路由表格
    private class RouteTable extends JTable {
        public RouteTable(TableModel tableModel) {
            super(tableModel);
            // 设置列宽
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(1).setMaxWidth(50);
            columnModel.getColumn(2).setMinWidth(100);
            columnModel.getColumn(2).setMaxWidth(150);
        }
        @Override
        public TableCellRenderer getCellRenderer(int row, int column) {
            return new CustomTableCellRenderer();
        }

    }
    // 自定义TableCellRenderer，用于将"开启"/"关闭"显示为特定颜色等样式
    private static class CustomTableCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof String) {
                String text = (String) value;
                if ("开启".equals(text)) {
                    setForeground(Color.GREEN); // 设置开启状态的文字颜色为绿色
                } else if ("关闭".equals(text)) {
                    setForeground(Color.RED); // 设置关闭状态的文字颜色为红色
                }
            }
            return this;
        }
    }
}
