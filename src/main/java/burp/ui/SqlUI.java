package burp.ui;

import burp.*;
import burp.bean.Config;
import burp.bean.Sql;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

import static burp.IParameter.*;
import static burp.dao.ConfigDAO.*;
import static burp.dao.SqlDAO.addSqli;
import static burp.dao.SqlDAO.getSqliList;
import static burp.utils.Utils.getSuffix;

public class SqlUI extends AbstractTableModel implements UIHandler, IMessageEditorController,IHttpListener {
    public IBurpExtenderCallbacks callbacks;
    private static final List<SqlUI.LogEntry> log = new ArrayList<>();
    private static final List<SqlUI.DataEntry> data = new ArrayList<>();
    private static final List<SqlUI.DataEntry> data2 = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public AbstractTableModel model = new MyModel();
    private int select_id;
    private JSplitPane splitPane1;
    private JSplitPane splitPane2;
    private JSplitPane splitPane3;
    private JScrollPane scrollPane1;
    private JTable originatable;
    private JScrollPane scrollPane2;
    private JTable datatable;
    private JPanel panel1;
    private JCheckBox startPluginbutton; // 开启插件按钮
    private JCheckBox delOriginalValuebutton; // 删除原始值按钮
    private JCheckBox whitedomainStatusbutton; // 开启域名白名单按钮、
    private JCheckBox enableCookiebutton; // 开启cookie按钮
    private JTextArea whitedomain;
    private JTextArea sqlpayload;
    private IMessageEditor HResponseTextEditor;
    private IMessageEditor HRequestTextEditor;
    private Boolean delOriginalValue; // 是否删除原始值
    private Boolean whitedomainStatus; // 是否开启域名白名单
    private Boolean enableCookie; // 是否开启cookie

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

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.registerHttpListener(this); // 注册被动扫描监听器
        JPanel jp = new JPanel(new BorderLayout());
        splitPane1 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 左右分割面板
        splitPane1.setResizeWeight(0.8);

        splitPane2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT); // 左边的上下分割面板
        splitPane2.setResizeWeight(0.5);


        splitPane3 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 左边上面的左右分割面板  table 分割
        splitPane3.setResizeWeight(0.5);

        originatable = new Table(SqlUI.this);
        scrollPane1 = new JScrollPane(originatable);  // 原始检测的table

        datatable = new Table_log(model);
        scrollPane2 = new JScrollPane(datatable);  // 日志的table

        splitPane3.setLeftComponent(scrollPane1);
        splitPane3.setRightComponent(scrollPane2);

        JSplitPane xjSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 请求与响应界面的分隔面板
        JTabbedPane ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(SqlUI.this, true);
        ltable.addTab("Request", HRequestTextEditor.getComponent());
        JTabbedPane rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(SqlUI.this, false);
        rtable.addTab("Response", HResponseTextEditor.getComponent());
        xjSplitPane.add(ltable, JSplitPane.LEFT);
        xjSplitPane.add(rtable, JSplitPane.RIGHT);
        xjSplitPane.setResizeWeight(0.5); // 设置调整权重为 0.5，使两个面板的宽度一样



        splitPane2.add(splitPane3,JSplitPane.TOP);
        splitPane2.add(xjSplitPane, JSplitPane.BOTTOM);


        // 面板
        panel1 = new JPanel();
        panel1.setLayout(new BoxLayout(panel1, BoxLayout.Y_AXIS));
        JPanel row1Panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startPluginbutton = new JCheckBox("启用插件");
        row1Panel.add(startPluginbutton);
        delOriginalValuebutton = new JCheckBox("删除原始值");
        row1Panel.add(delOriginalValuebutton);
        whitedomainStatusbutton = new JCheckBox("开启域名白名单");
        row1Panel.add(whitedomainStatusbutton);
        enableCookiebutton = new JCheckBox("开启cookie检测");
        row1Panel.add(enableCookiebutton);
        panel1.add(row1Panel);


        // 初始化删除按钮是否选中
        Config delOriginalValueSelect = getValueByModuleAndType("sql","delOriginalValue");
        if (delOriginalValueSelect.getValue().equals("true")){
            delOriginalValuebutton.setSelected(true);
        }else {
            delOriginalValuebutton.setSelected(false);
        }
        // 初始化域名白名单按钮是否选中
        Config whitedomainStatusSelect = getValueByModuleAndType("sql","whitedomainStatus");
        if (whitedomainStatusSelect.getValue().equals("true")){
            whitedomainStatusbutton.setSelected(true);
        }else {
            whitedomainStatusbutton.setSelected(false);
        }
        // 初始化cookie检测按钮是否选中
        Config enableCookieSelect = getValueByModuleAndType("sql","enableCookie");
        if (enableCookieSelect.getValue().equals("true")){
            enableCookiebutton.setSelected(true);
        }else {
            enableCookiebutton.setSelected(false);
        }


        // 当选中开启插件时，禁用白名单域名和sqlpayload
        startPluginbutton.addItemListener(new ItemListener() {
            @Override public void itemStateChanged(ItemEvent e) {
                if (startPluginbutton.isSelected()){
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("startPlugin");
                    config.setValue("true");
                    updateConfigSetting(config);
                    whitedomain.setEnabled(false);
                    sqlpayload.setEnabled(false);
                }else {
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("startPlugin");
                    config.setValue("false");
                    updateConfigSetting(config);
                    whitedomain.setEnabled(true);
                    sqlpayload.setEnabled(true);
                }
        }});
        // 当选中删除原始值时，设置delOriginalValue为true
        delOriginalValuebutton.addItemListener(new ItemListener() {
            @Override public void itemStateChanged(ItemEvent e) {
                if (delOriginalValuebutton.isSelected()){
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("delOriginalValue");
                    config.setValue("true");
                    updateConfigSetting(config);
                }else {
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("delOriginalValue");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
        }});
        // 当选中开启域名白名单时，设置whitedomainStatus为true
        whitedomainStatusbutton.addItemListener(new ItemListener() {
            @Override public void itemStateChanged(ItemEvent e) {
                if (whitedomainStatusbutton.isSelected()){
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("whitedomainStatus");
                    config.setValue("true");
                    updateConfigSetting(config);
                }else {
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("whitedomainStatus");
                    config.setValue("false");
                    updateConfigSetting(config);
                }

        }});
        // 当选中开启cookie检测时，设置enableCookie为true
        enableCookiebutton.addItemListener(new ItemListener() {
            @Override public void itemStateChanged(ItemEvent e) {
                if(enableCookiebutton.isSelected()){
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("enableCookie");
                    config.setValue("true");
                    updateConfigSetting(config);
                }else {
                    Config config = new Config();
                    config.setModule("sql");
                    config.setType("enableCookie");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
        }});
        JPanel row2Panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refershButton = new JButton("刷新表格数据");
        row2Panel.add(refershButton);

        JButton delallButton = new JButton("删除表格全部");
        row2Panel.add(delallButton);

        JButton saveDomainButton = new JButton("保存白名单域名");
        row2Panel.add(saveDomainButton);
        panel1.add(row2Panel);

        JButton saveSqlPayloadButton = new JButton("保存sqlpayload");
        row2Panel.add(saveSqlPayloadButton);
        panel1.add(row2Panel);

        // 当点击刷新表格数据时，刷新表格数据
        refershButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                fireTableDataChanged();
                model.fireTableDataChanged();
        }});
        // 当点击删除表格全部时，删除表格全部数据
        delallButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                log.clear();
                data.clear();
                data2.clear();
                HResponseTextEditor.setMessage(new byte[0],false);
                HResponseTextEditor.setMessage(new byte[0],false);
                fireTableDataChanged();
                model.fireTableDataChanged();
        }});
        // 当点击保存表格数据时，保存表格数据
        saveDomainButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                // 获取白名单域名
                String whitedomainText = whitedomain.getText();
                if ("白名单域名 eg:www.baidu.com,不填则不运行插件".contains(whitedomainText)){
                    JOptionPane.showMessageDialog(null, "白名单域名不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Config config = new Config();
                config.setModule("sql");
                config.setType("whiteSqlDomain");
                config.setValue(whitedomainText);
                updateConfigSetting(config);
                whitedomain.setText(whitedomainText);
        }});
        // 当点击保存sqlpayload时，保存sqlpayload
        saveSqlPayloadButton.addActionListener(new ActionListener() {
            @Override public void actionPerformed(ActionEvent e) {
                // 获取sqlpayload
                String sqlpayloadText = sqlpayload.getText();
                if ("".equals(sqlpayloadText)){
                    JOptionPane.showMessageDialog(null, "sqlpayload不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Sql sql = new Sql();
                sql.setSql(sqlpayloadText);
                addSqli(sql);
                sqlpayload.setText(sqlpayloadText);
        }});

        JLabel whiteDomainText = new JLabel("白名单域名");
        panel1.add(whiteDomainText);


        whitedomain = new JTextArea();
        // 获取白名单域名并设置到whitedomain
        Config whitedomainConfig = getValueByModuleAndType("sql", "whiteSqlDomain");
        whitedomain.setText(whitedomainConfig.getValue());
        whitedomain.setFont(whitedomain.getFont().deriveFont(Font.PLAIN, 12)); // 调整字体大小
        whitedomain.setRows(1); // 设置行数
        whitedomain.setColumns(20); // 设置列数
        JScrollPane whiteDomainScrollPane = new JScrollPane(whitedomain);
        panel1.add(whiteDomainScrollPane);

        JLabel sqlLableText = new JLabel("sql注入关键字,区分大小写");
        panel1.add(sqlLableText);

        StringBuilder sqlColumnNamesBuilder = new StringBuilder();
        List<Sql> sqliList = getSqliList();
        for (Sql sql : sqliList) {
            sqlColumnNamesBuilder.append(sql.getSql()).append("\n");
        }
        String sqlColumnNames = sqlColumnNamesBuilder.toString();

        sqlpayload = new JTextArea();
        sqlpayload.setText(sqlColumnNames);
        sqlpayload.setFont(sqlpayload.getFont().deriveFont(Font.PLAIN, 12)); // 调整字体大小
        sqlpayload.setRows(5); // 设置行数
        sqlpayload.setColumns(20); // 设置列数
        JScrollPane lowAuthScrollPane = new JScrollPane(sqlpayload);
        panel1.add(lowAuthScrollPane);
        splitPane1.setDividerSize(3);
        splitPane2.setDividerSize(3);
        splitPane3.setDividerSize(1);
        splitPane1.add(splitPane2, JSplitPane.LEFT);
        splitPane1.add(panel1, JSplitPane.RIGHT);

        jp.add(splitPane1);




        originatable.addMouseListener(new MouseAdapter() {@Override public void mouseClicked(MouseEvent e) {
            model.fireTableDataChanged();
            super.mouseClicked(e);
        }});
        return jp;
    }


    public void CheckSQLi(IHttpRequestResponse[] responses){
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists= analyzeRequest.getParameters();
        List<Sql> sqliPayload = getSqliList();
        Config whitedomainStatusConfig = getValueByModuleAndType("sql","whitedomainStatus");
        whitedomainStatus = whitedomainStatusConfig.getValue().equals("true");
        Config delOriginalValueConfig = getValueByModuleAndType("sql","delOriginalValue");
        delOriginalValue = delOriginalValueConfig.getValue().equals("true");
        Config enableCookieConfig = getValueByModuleAndType("sql","enableCookie");
        enableCookie = enableCookieConfig.getValue().equals("true");
        // 参数为空，直接返回
        if (paraLists.size() == 0){
            return;
        }
        // url 中为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s) || url.contains(s)){
                return;
            }
        }
        // url 不是白名单域名，直接返回
        if (whitedomainStatus){
            Config whiteSqlDomain = getValueByModuleAndType("sql", "whiteSqlDomain");
            if (!url.contains(whiteSqlDomain.getValue())){
                JOptionPane.showMessageDialog(null, "url不在白名单域名内", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        // 原始请求包发送一次
        // 原始请求
        List<String> originalheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        byte[] byte_Request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        int len = byte_Request.length;
        byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
        byte[] postMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
        IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
        byte[] responseBody = originalRequestResponse.getResponse();
        int originalLength = 0;
        if (responseBody != null) {
            IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
            List<String> headers = originalReqResponse.getHeaders();
            for (String header : headers) {
                if (header.contains("Content-Length")) {
                    originalLength = Integer.parseInt(header.split(":")[1].trim());
                    break;
                }
            }
        }
        if (originalLength == 0) {
            originalLength = Integer.parseInt(String.valueOf(responseBody.length));
        }
        List<String> listErrorKey = new ArrayList<>();
        String sqliErrorKey = getValueByModuleAndType("sql", "sqliErrorKey").getValue();
        String[] sqliErrorKeyValue = sqliErrorKey.split("\\|");
        listErrorKey.addAll(Arrays.asList(sqliErrorKeyValue));
        int logid = addLog(method, url,originalLength,originalRequestResponse);
        for (IParameter para : paraLists){
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_COOKIE || para.getType() == PARAM_JSON){
                String paraName = para.getName();
                String paraValue = para.getValue();
                // 判断参数是否在url中
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY){
                    if (paraName.equals("")){
                        return;
                    }
                    for (Sql sql : sqliPayload) {
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = sql.getSql();
                        if (sqlPayload.equals("")){
                            return;
                        }
                        // 是否删除原始的参数值
                        if (delOriginalValue){
                            payload = sqlPayload;
                        }else {
                            payload = paraValue + sqlPayload;
                        }
                        long startTime = System.currentTimeMillis();
                        IParameter iParameter = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
                        long endTime = System.currentTimeMillis();
                        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                        int statusCode = analyzeResponse.getStatusCode();
                        String responseTime = String.valueOf(endTime - startTime);
                        byte[] sqlresponseBody = newRequestResponse.getResponse();
                        int sqlLength = 0;
                        if (sqlresponseBody != null) {
                            // 判断有无Content-Length字段
                            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                            List<String> sqlHeaders = ReqResponse.getHeaders();
                            for (String header : sqlHeaders) {
                                if (header.contains("Content-Length")) {
                                    sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                    break;
                                }
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            for (String errorKey : listErrorKey) {
                                if (sqlResponseBody.contains(errorKey)){
                                    errkey = "√";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }

                        addDataLog(logid,paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength-originalLength)),errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }

                }
                else if(enableCookie && para.getType() == PARAM_COOKIE){
                    if (paraName.equals("")){
                        return;
                    }
                    for (Sql sql : sqliPayload) {
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = sql.getSql();
                        if (sqlPayload.equals("")){
                            return;
                        }
                        // 是否删除原始的参数值
                        if (delOriginalValue){
                            payload = sqlPayload;
                        }else {
                            payload = paraValue + sqlPayload;
                        }
                        long startTime = System.currentTimeMillis();
                        IParameter iParameter = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
                        long endTime = System.currentTimeMillis();
                        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                        int statusCode = analyzeResponse.getStatusCode();
                        String responseTime = String.valueOf(endTime - startTime);
                        byte[] sqlresponseBody = newRequestResponse.getResponse();
                        int sqlLength = 0;
                        if (sqlresponseBody != null) {
                            // 判断有无Content-Length字段
                            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                            List<String> sqlHeaders = ReqResponse.getHeaders();
                            for (String header : sqlHeaders) {
                                if (header.contains("Content-Length")) {
                                    sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                    break;
                                }
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            for (String errorKey : listErrorKey) {
                                if (sqlResponseBody.contains(errorKey)){
                                    errkey = "√";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }
                        addDataLog(logid,paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength-originalLength)),errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }

                }
                else if (para.getType() == PARAM_JSON){

                    for (Sql sql : sqliPayload) {
                        String errkey = "x";
                        String payload = sql.getSql();
                        String reqValue = "";
                        String data = new String(body);
                        if (Utils.isJSON(data)){//当参数的值是json格式
                            try {
                                data = Utils.updateJSONValue(data,payload);
                                byte[] message = Utils.helpers.buildHttpMessage(reqheaders, data.getBytes());
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
                                // xm17: 考虑服务器被waf了  然后返回时间很长的情况
                                long startTime = System.currentTimeMillis();
                                IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                                long endTime = System.currentTimeMillis();
                                int statusCode = analyzeResponse.getStatusCode();
                                String responseTime = String.valueOf(endTime - startTime);
                                byte[] sqlresponseBody = newRequestResponse.getResponse();
                                int sqlLength = 0;
                                if (sqlresponseBody != null) {
                                    // 判断有无Content-Length字段
                                    IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                                    List<String> sqlHeaders = ReqResponse.getHeaders();
                                    for (String header : sqlHeaders) {
                                        if (header.contains("Content-Length")) {
                                            sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                            break;
                                        }
                                    }
                                    // 判断body中是否有errorkey关键字
                                    String sqlResponseBody = new String(sqlresponseBody);
                                    for (String errorKey : listErrorKey) {
                                        if (sqlResponseBody.contains(errorKey)){
                                            errkey = "√";
                                            break;
                                        }
                                    }
                                }
                                if (sqlLength == 0) {
                                    sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                                }
                                addDataLog(logid,"json", data, sqlLength, String.valueOf(Math.abs(sqlLength-originalLength)),errkey, responseTime, String.valueOf(statusCode), newRequestResponse);

                            } catch (Exception e) {
                                Utils.stderr.println(e.getMessage());

                            }
                        }else {
                            return;
                        }

                    }
                    break;
                }

            }
        }

        updateLog(logid, method, url,originalLength,originalRequestResponse);
    }



    public int addLog(String method ,String url,int length,IHttpRequestResponse requestResponse){
        synchronized (log){
            int id = log.size();
            log.add(new LogEntry(id,method,url,length,"正在检测",requestResponse));
            fireTableRowsInserted(id,id);
            fireTableDataChanged();
            return id;
        }
    }
    public void updateLog(int index, String method, String url,int length,IHttpRequestResponse requestResponse) {
        synchronized (log) {
            if (index >= 0 && index < log.size()) {
                log.set(index, new LogEntry(index, method, url,length, "完成",requestResponse));
                fireTableRowsUpdated(index, index);  // 更新指定行
            }
        }
    }
    public void addDataLog(int selectId,String key,String value, int length, String change,String errkey, String time,String status,IHttpRequestResponse requestResponse){

        synchronized (data2){
            int id = data2.size();
            data2.add(new DataEntry(id,selectId,key,value,length,change,errkey,time,status,requestResponse));
            fireTableRowsInserted(id,id);
            fireTableDataChanged();
        }
    }

    @Override
    public String getTabName() {
        return "sql";
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
            case 0:
                return log.get(rowIndex).id;
            case 1:
                return log.get(rowIndex).method;
            case 2:
                return log.get(rowIndex).url;
            case 3:
                return log.get(rowIndex).length;
            case 4:
                return log.get(rowIndex).status;
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
       switch (column){
           case 0:
               return "id";
           case 1:
               return "method";
           case 2:
               return "url";
           case 3:
               return "length";
           case 4:
               return "status";
           default:
               return null;
       }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        Config enableSqli = getValueByModuleAndType("sql", "startPlugin");
        boolean scanProxy = enableSqli.getValue().equals("true");
        if (scanProxy && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest){
            synchronized (log){
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        CheckSQLi(new IHttpRequestResponse[]{messageInfo});
                    }
                });
                thread.start();
            }
        }
    }

    public class LogEntry {
        final int id;
        final String method;
        final String url;
        final int length;
        final String status;
        final IHttpRequestResponse requestResponse;

        LogEntry(int id, String method, String url,int length,String status,IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.length = length;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }
    private class Table extends JTable{
        public Table(AbstractTableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            SqlUI.LogEntry logEntry = log.get(rowIndex);
            select_id = logEntry.id;
            data.clear();
            for (int i = 0; i < data2.size(); i++) {
                if (data2.get(i).selectId == select_id){
                    data.add(data2.get(i));
                }
            }


            model.fireTableRowsInserted(data.size(),data.size());
            model.fireTableDataChanged();
            HRequestTextEditor.setMessage(logEntry.requestResponse.getRequest(),true);
            if (logEntry.requestResponse.getResponse() == null){
                HResponseTextEditor.setMessage(new byte[0],false);
            }else {
                HResponseTextEditor.setMessage(logEntry.requestResponse.getResponse(),false);
            }
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    private class Table_log extends JTable{
        public Table_log(AbstractTableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {

            SqlUI.DataEntry dataEntry = data.get(rowIndex);
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(),true);
            if (dataEntry.requestResponse.getResponse() == null){
                HResponseTextEditor.setMessage(new byte[0],false);
            }else {
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(),false);
            }
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    class MyModel extends AbstractTableModel{

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex){
                case 0:
                    return data.get(rowIndex).id;
                case 1:
                    return data.get(rowIndex).key;
                case 2:
                    return data.get(rowIndex).value;
                case 3:
                    return data.get(rowIndex).length;
                case 4:
                    return data.get(rowIndex).change;
                case 5:
                    return data.get(rowIndex).errkey;
                case 6:
                    return data.get(rowIndex).time;
                case 7:
                    return data.get(rowIndex).status;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0:
                    return "id";
                case 1:
                    return "参数";
                case 2:
                    return "参数值";
                case 3:
                    return "响应长度";
                case 4:
                    return "变化";
                case 5:
                    return "报错";
                case 6:
                    return "时间";
                case 7:
                    return "返回码";
                default:
                    return null;
            }
        }
    }
    public class DataEntry{
        final int id;
        final int selectId;
        final String key;
        final String value;
        final int length;
        final String change;
        final String errkey;
        final String time;
        final String status;
        final IHttpRequestResponse requestResponse;

        public DataEntry(int id, int selectId, String key, String value, int length, String change,String errkey, String time, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.selectId = selectId;
            this.key = key;
            this.value = value;
            this.length = length;
            this.change = change;
            this.errkey = errkey;
            this.time = time;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }
}
