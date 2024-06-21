package burp.ui;

import burp.*;
import burp.bean.AuthBean;
import burp.bean.RouteBean;
import burp.utils.ExpressionUtils;
import burp.utils.Utils;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

import static burp.dao.RouteDao.*;
import static burp.utils.Utils.getSuffix;

public class RouteUI implements UIHandler, IMessageEditorController, IHttpListener {
    private static IHttpRequestResponse currentlyDisplayedItem;
    private static final List<RouteEntry> data = new ArrayList<>();
    private static final List<IssusEntry> dataIssus = new ArrayList<>();
    private static final List<String> parameterList = new ArrayList<>();
    private static final List<String> urlHashList = new ArrayList<>();
    public AbstractTableModel dataModel = new RouteModel();
    public AbstractTableModel issusModel = new IssusModel();
    private JPanel panel;
    private JButton refreshButton;
    private JButton clearButton;
    private JCheckBox passiveCheckBox;
    private JTable tableRule;
    private boolean passive = false;
    private static JTable tableIssus;

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, final IHttpRequestResponse iHttpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && passive) {
            synchronized (dataIssus) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(iHttpRequestResponse);
                    }
                });
                thread.start();
            }
        }
    }

    public static void Check(IHttpRequestResponse iHttpRequestResponse) {
        // 草,这里的iHttpRequestResponse.getResponse()居然是null
        if (iHttpRequestResponse.getResponse() == null) {
            return;
        }
        IRequestInfo iRequestInfo = Utils.helpers.analyzeRequest(iHttpRequestResponse);
        String url = iRequestInfo.getUrl().toString();
        String method = iRequestInfo.getMethod();
        String request = Utils.helpers.bytesToString(iHttpRequestResponse.getRequest());
        String path = iRequestInfo.getUrl().getPath();
        List<IParameter> paraLists = iRequestInfo.getParameters();

        // 对url进行hash去重
        for (IParameter paraList : paraLists) {
            String paraName = paraList.getName();
            parameterList.add(paraName);
        }
        if (!checkUrlHash(method + url + parameterList)) {
            return;
        }

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

        // url 中为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s)) {
                return;
            }
        }


        // 获取payload
        List<RouteBean> routeList = getRouteListNoClose();

        for (RouteBean routeBean : routeList) {
            List<String> reqLists = append(path, routeBean.getPath());
            for (String reqList : reqLists) {
                if (Objects.equals(method, "GET")) {
                    String new_request = request.replaceFirst(path, reqList);
                    IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                    ExpressionUtils expressionUtils = new ExpressionUtils(response);
                    boolean process = expressionUtils.process(routeBean.getExpress());
                    if (process) {
                        addIssus(expressionUtils.getUrl(), routeBean.getName(), String.valueOf(expressionUtils.getCode()));
                    }
                } else if (Objects.equals(method, "POST")) {
                    String new_request = request.replaceFirst(path, reqList);
                    IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), Utils.helpers.stringToBytes(new_request));
                    ExpressionUtils expressionUtils = new ExpressionUtils(response);
                    boolean process = expressionUtils.process(routeBean.getExpress());
                    if (process) {
                        addIssus(expressionUtils.getUrl(), routeBean.getName(), String.valueOf(expressionUtils.getCode()));
                    }
                }
            }

        }
    }

    private static boolean checkUrlHash(String url) {
        parameterList.clear();
        String md5 = DigestUtils.md5DigestAsHex(url.getBytes());
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

    private void setupData() {
        Utils.callbacks.registerHttpListener(this);
        // 当scanButton被点击时，变为Stop
        refreshButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                data.clear();
                List<RouteBean> routeList = getRouteList();
                // 添加到RouteModel
                for (RouteBean routeBean : routeList) {
                    data.add(new RouteEntry(routeBean.getName(), routeBean.getPath(), routeBean.getExpress(), routeBean.getEnable()));
                }
                dataModel.fireTableDataChanged();
                tableRule.updateUI();
            }
        });

        clearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dataIssus.clear();
                tableIssus.updateUI();
            }
        });


        List<RouteBean> routeList = getRouteList();
        // 添加到RouteModel
        for (RouteBean routeBean : routeList) {
            data.add(new RouteEntry(routeBean.getName(), routeBean.getPath(), routeBean.getExpress(), routeBean.getEnable()));
        }

        // 监听表格第一列是否被点击
        tableRule.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = tableRule.rowAtPoint(e.getPoint());
                int col = tableRule.columnAtPoint(e.getPoint());
                if (col == 0) {
                    if (data.get(row).isEnable() == 1) {
                        closeOrOpenRoute(0, data.get(row).getName());
                        data.get(row).enable = 0;
                        dataModel.fireTableDataChanged();
                    } else {
                        closeOrOpenRoute(1, data.get(row).getName());
                        data.get(row).enable = 1;
                        dataModel.fireTableDataChanged();
                    }
                    tableRule.updateUI();
                }
            }
        });

        passiveCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 当被选中时
                if (passiveCheckBox.isSelected()) {
                    // 开启被动扫描
                    passiveCheckBox.setSelected(true);
                    passive = true;
                } else {
                    // 关闭被动扫描
                    passiveCheckBox.setSelected(false);
                    passive = false;
                }
            }
        });


    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = 0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        JLabel label = new JLabel("RouteScan");
        panel.add(label, gbc);
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST; // 按钮位于最左边
        refreshButton = new JButton("Refersh");
        panel.add(refreshButton, gbc);

        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST; // 按钮位于最左边
        clearButton = new JButton("Clear");
        panel.add(clearButton, gbc);

        gbc.gridx = 3;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST; // 按钮位于最左边
        passiveCheckBox = new JCheckBox("Scan");
        panel.add(passiveCheckBox, gbc);


        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 1.0d;
        gbc.weighty = 1.0d;
        gbc.gridwidth = 4;
        gbc.fill = 1;
        tableIssus = new JTable(new IssusModel());
        tableIssus.getColumnModel().getColumn(0).setPreferredWidth(5);
        panel.add(new JScrollPane(tableIssus), gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 1.0d;
        gbc.weighty = 1.0d;
        gbc.gridwidth = 4;
        gbc.fill = 1;
        tableRule = new JTable(dataModel);
        // 设置列的宽度
        tableRule.getColumnModel().getColumn(0).setPreferredWidth(10);
        // 设置第一列为复选框
        tableRule.getColumnModel().getColumn(0).setCellRenderer(new CheckBoxRenderer());
        panel.add(new JScrollPane(tableRule), gbc);
    }

    // 创建一个复选框渲染器
    class CheckBoxRenderer extends JCheckBox implements TableCellRenderer {
        public CheckBoxRenderer() {
            this.setHorizontalAlignment(JLabel.CENTER);
        }

        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            this.setSelected(((Boolean) value).booleanValue());
            return this;
        }
    }


    public static void addIssus(String url, String name, String Status) {
        synchronized (dataIssus) {
            // 判断是否已经存在
            for (IssusEntry issusEntry : dataIssus) {
                if (issusEntry.getUrl().equals(url)) {
                    return;
                }
            }
            int size = dataIssus.size();
            dataIssus.add(new IssusEntry(size, name, url, Status));
            tableIssus.updateUI();
        }
    }

    public static class IssusEntry {
        private int id;
        private String url;
        private String name;
        private String status;

        public IssusEntry(int id, String name, String url, String status) {
            this.id = id;
            this.url = url;
            this.name = name;
            this.status = status;
        }

        public int getId() {
            return id;
        }

        public void setId(int id) {
            this.id = id;
        }

        public String getUrl() {
            return url;
        }

        public String getName() {
            return name;
        }

        public String getStatus() {
            return status;
        }
    }

    // 问题表格模型
    static class IssusModel extends AbstractTableModel {

        public int getColumnCount() {
            return 4;
        }

        public int getRowCount() {
            return dataIssus.size();
        }

        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "#";
                case 1:
                    return "Issus Name";
                case 2:
                    return "URL";
                case 3:
                    return "Status";
                default:
                    return null;
            }
        }

        public Object getValueAt(int row, int col) {
            IssusEntry issusEntry = dataIssus.get(row);
            switch (col) {
                case 0:
                    return issusEntry.getId();
                case 1:
                    return issusEntry.getName();
                case 2:
                    return issusEntry.getUrl();
                case 3:
                    return issusEntry.getStatus();
                default:
                    return null;
            }
        }


    }


    public void addData(int enable, String name, String path, String express) {
        synchronized (data) {
            data.add(new RouteEntry(name, path, express, enable));
            dataModel.fireTableDataChanged();
            dataModel.fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }
    }


    public static class RouteEntry {
        private String name;
        private String path;
        private String express;
        private int enable;

        public RouteEntry(String name, String path, String express, int enable) {
            this.name = name;
            this.path = path;
            this.express = express;
            this.enable = enable;
        }

        public String getName() {
            return name;
        }

        public String getPath() {
            return path;
        }

        public String getExpress() {
            return express;
        }

        public int isEnable() {
            return enable;
        }
    }


    // 路由表格模型
    static class RouteModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RouteEntry routeEntry = data.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return routeEntry.isEnable() == 1;
                case 1:
                    return routeEntry.getName();
                case 2:
                    return routeEntry.getPath();
                case 3:
                    return routeEntry.getExpress();
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Enable";
                case 1:
                    return "Name";
                case 2:
                    return "Path";
                case 3:
                    return "Express";
                default:
                    return null;
            }
        }
    }


    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "RouteScan";
    }
}
