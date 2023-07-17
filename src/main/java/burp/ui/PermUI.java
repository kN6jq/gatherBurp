package burp.ui;

import burp.*;
import burp.bean.Perm;
import burp.utils.Utils;
import com.sun.org.apache.bcel.internal.generic.IF_ACMPEQ;


import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static burp.dao.PermDAO.*;
import static burp.utils.Utils.getSuffix;

public class PermUI extends AbstractTableModel implements UIHandler, IMessageEditorController, IHttpListener {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private static final List<PermUI.LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor originarequest;
    private IMessageEditor originaresponse;
    private IMessageEditor lowerrequest;
    private IMessageEditor lowerresponse;
    private IMessageEditor norequest;
    private IMessageEditor noresponse;
    private boolean scanProxy = false;

    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    @Override
    public void init() {

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        callbacks.registerHttpListener(this); // 注册被动扫描监听器
        Utils.callbacks = callbacks;
        JPanel jp = new JPanel(new BorderLayout());
        JSplitPane SplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 主分隔面板
        SplitPane.setResizeWeight(0.8);
        JSplitPane mSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); // 主分隔面板

        JTable urlTable = new PermUI.URLTable(PermUI.this);
        JScrollPane jScrollPane = new JScrollPane(urlTable); // 滚动条

        JSplitPane xjSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 请求与响应界面的分隔面板

        JTabbedPane ltable = new JTabbedPane();
        originarequest = callbacks.createMessageEditor(PermUI.this, false);
        originaresponse = callbacks.createMessageEditor(PermUI.this, false);
        lowerrequest = callbacks.createMessageEditor(PermUI.this, false);
        lowerresponse = callbacks.createMessageEditor(PermUI.this, false);
        norequest = callbacks.createMessageEditor(PermUI.this, false);
        noresponse = callbacks.createMessageEditor(PermUI.this, false);

        JSplitPane originalSplitPane = new JSplitPane(1);
        originalSplitPane.setLeftComponent(originarequest.getComponent());
        originalSplitPane.setRightComponent(originaresponse.getComponent());
        originalSplitPane.setResizeWeight(0.5D);
        ltable.addTab("原始数据包", originalSplitPane);

        JSplitPane lowerSplitPane = new JSplitPane(1);
        lowerSplitPane.setLeftComponent(lowerrequest.getComponent());
        lowerSplitPane.setRightComponent(lowerresponse.getComponent());
        lowerSplitPane.setResizeWeight(0.5D);
        ltable.addTab("低权限数据包", lowerSplitPane);

        JSplitPane noSplitPane = new JSplitPane(1);
        noSplitPane.setLeftComponent(norequest.getComponent());
        noSplitPane.setRightComponent(noresponse.getComponent());
        noSplitPane.setResizeWeight(0.5D);
        ltable.addTab("未授权数据包", noSplitPane);

        xjSplitPane.setLeftComponent(ltable);

        mSplitPane.add(jScrollPane, "left");
        mSplitPane.add(xjSplitPane, "right");


        JPanel jPanel = new JPanel();
        jPanel.setLayout(new BoxLayout(jPanel, BoxLayout.Y_AXIS));

        JPanel row1Panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JRadioButton startplugin = new JRadioButton("启用插件");
        row1Panel.add(startplugin);
        JButton saveButton = new JButton("保存数据");
        row1Panel.add(saveButton);
        JButton deleteButton = new JButton("删除历史数据");
        row1Panel.add(deleteButton);
        jPanel.add(row1Panel);


        JPanel row2Panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refershButton = new JButton("刷新表格数据");
        row2Panel.add(refershButton);
        JButton delselectButton = new JButton("删除表格选中");
        row2Panel.add(delselectButton);
        JButton delallButton = new JButton("删除表格全部");
        row2Panel.add(delallButton);
        jPanel.add(row2Panel);

        JLabel whiteDomainText = new JLabel("白名单域名");
        jPanel.add(whiteDomainText);
        Perm perm = getPerm();
        JTextArea whiteDomain = new JTextArea();
        whiteDomain.setFont(whiteDomain.getFont().deriveFont(Font.PLAIN, 12)); // 调整字体大小
        whiteDomain.setText(perm.getDomain());
        whiteDomain.setRows(1); // 设置行数
        whiteDomain.setColumns(20); // 设置列数
        JScrollPane whiteDomainScrollPane = new JScrollPane(whiteDomain);
        jPanel.add(whiteDomainScrollPane);

        JLabel lowAuthText = new JLabel("低权限认证关键字,区分大小写");
        jPanel.add(lowAuthText);

        JTextArea lowAuth = new JTextArea();
        lowAuth.setText(perm.getLow().replaceAll("\\|", "\n"));
        lowAuth.setFont(lowAuth.getFont().deriveFont(Font.PLAIN, 12)); // 调整字体大小
        lowAuth.setRows(5); // 设置行数
        lowAuth.setColumns(20); // 设置列数
        JScrollPane lowAuthScrollPane = new JScrollPane(lowAuth);
        jPanel.add(lowAuthScrollPane);

        JLabel noAuthText = new JLabel("未授权认证关键字,区分大小写");
        jPanel.add(noAuthText);

        JTextArea noAuth = new JTextArea();
        noAuth.setText(perm.getNo().replaceAll("\\|", "\n"));
        noAuth.setFont(noAuth.getFont().deriveFont(Font.PLAIN, 12)); // 调整字体大小
        noAuth.setRows(5); // 设置行数
        noAuth.setColumns(20); // 设置列数
        JScrollPane noAuthScrollPane = new JScrollPane(noAuth);
        jPanel.add(noAuthScrollPane);

        refershButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fireTableDataChanged();
            }
        });
        delselectButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                originarequest.setMessage(new byte[0], false);
                originaresponse.setMessage(new byte[0], false);
                lowerrequest.setMessage(new byte[0], false);
                lowerresponse.setMessage(new byte[0], false);
                norequest.setMessage(new byte[0], false);
                noresponse.setMessage(new byte[0], false);
                int[] rows = urlTable.getSelectedRows();
                for (int i = rows.length - 1; i >= 0; i--) {
                    int row = urlTable.convertRowIndexToModel(rows[i]);
                    log.remove(row);
                    fireTableRowsDeleted(row, row);
                    fireTableDataChanged();
                }
            }
        });
        delallButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                originarequest.setMessage(new byte[0], false);
                originaresponse.setMessage(new byte[0], false);
                lowerrequest.setMessage(new byte[0], false);
                lowerresponse.setMessage(new byte[0], false);
                norequest.setMessage(new byte[0], false);
                noresponse.setMessage(new byte[0], false);
                log.clear();
                fireTableDataChanged();
            }
        });

        saveButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String domainText = whiteDomain.getText();
                String lowAuthText = lowAuth.getText();
                String noAuthText = noAuth.getText();
                if (domainText.equals("白名单域名 eg:www.baidu.com,不填则不运行插件")){
                    JOptionPane.showMessageDialog(null, "请填写白名单域名", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Perm perm = new Perm();
                perm.setDomain(domainText.replace("\n", "|"));
                perm.setLow(lowAuthText.replace("\n", "|"));
                perm.setNo(noAuthText.replace("\n", "|"));
                int i = savePerm(perm);
                if (i == 1) {
                    JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
                }else {
                    JOptionPane.showMessageDialog(null, "保存失败", "提示", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        deleteButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int i = deletePerm();
                if (i == 1) {
                    JOptionPane.showMessageDialog(null, "删除缓存数据成功", "提示", JOptionPane.INFORMATION_MESSAGE);
                }else {
                    JOptionPane.showMessageDialog(null, "删除缓存数据失败", "提示", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 添加单选框状态变化的监听器
        startplugin.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) { // 单选框被选中
                    scanProxy = true;
                    whiteDomain.setEnabled(false); // 禁用输入框
                    lowAuth.setEnabled(false); // 禁用输入框
                    noAuth.setEnabled(false); // 禁用输入框
                } else { // 单选框未被选中
                    whiteDomain.setEnabled(true); // 启用输入框
                    lowAuth.setEnabled(true); // 启用输入框
                    noAuth.setEnabled(true); // 启用输入框
                }
            }
        });

        SplitPane.setDividerSize(3);
        SplitPane.add(mSplitPane, JSplitPane.LEFT);
        SplitPane.add(jPanel, JSplitPane.RIGHT);

        jp.add(SplitPane);
        return jp;
    }

    public void CheckPermBypass(IHttpRequestResponse[] responses){
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();

        try {
            List<String> suffix = getSuffix();
            if (suffix.size() > 0) {
                for (String s : suffix) {
                    if (url.endsWith(s) || url.contains(s)) {
                        return;
                    }
                }
            }


            Perm perm = getPerm();
            if (perm.getDomain() != null && !perm.getDomain().equals("")){
                if (!url.contains(perm.getDomain())){
                    Utils.stderr.println("测试目标不在白名单域名内");
                    return;
                }
            }else {
                JOptionPane.showMessageDialog(null, "请先填写白名单域名", "提示", JOptionPane.ERROR_MESSAGE);
                return;
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
            if (originallength.equals("")) {
                originallength = String.valueOf(responseBody.length);
            }



            // 低权限请求
            List<String> lowheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String lowAuthText = perm.getLow();
            if (lowAuthText.contains("|")) {
                String[] lowAuths = lowAuthText.split("\\|");
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
            }else {
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
            if (lowlength.equals("")) {
                lowlength = String.valueOf(lowresponseBody.length);
            }



            // 无权限请求
            List<String> noheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String noAuthText = perm.getNo();
            if (noAuthText.contains("|")) {
                String[] noAuths = noAuthText.split("\\|");
                for (String noAuth : noAuths) {
                    noheaders.removeIf(noheader -> noheader.contains(noAuth));
                }
            }else {
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
            if (nolength.equals("")) {
                nolength = String.valueOf(noresponseBody.length);
            }
            String isSuccess = "×";
            if (originallength.equals(lowlength) && lowlength.equals(nolength)) {
                isSuccess = "√";
            }else {
                isSuccess = "×";
            }

            add(extensionMethod,url,originallength,lowlength,nolength,isSuccess,baseRequestResponse,lowRequestResponse,noRequestResponse);
        }catch (Exception e){
            add(extensionMethod,url,"0","0","0","×",baseRequestResponse,null,null);
            Utils.stderr.println(e.getMessage());
        }

    }


    private void add(String method, String url, String originalength, String lowlength, String nolength,String isSuccess, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
        synchronized (log){
            int id = log.size();
            log.add(new PermUI.LogEntry(id, method, url, originalength, lowlength, nolength,isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse));
            fireTableRowsInserted(id, id);
            fireTableDataChanged();
        }
    }

    @Override
    public String getTabName() {
        return "Perm";
    }

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
        switch (columnIndex){
            case 0:return log.get(rowIndex).id;
            case 1:return log.get(rowIndex).method;
            case 2:return log.get(rowIndex).url;
            case 3:return log.get(rowIndex).originalength;
            case 4:return log.get(rowIndex).lowlength;
            case 5:return log.get(rowIndex).nolength;
            case 6:return log.get(rowIndex).isSuccess;
            default:return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:return "id";
            case 1:return "method";
            case 2:return "url";
            case 3:return "originalength";
            case 4:return "lowlength";
            case 5:return "nolength";
            case 6:return "isSuccess";
            default:return null;
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (scanProxy && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest){
            synchronized (log){
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        CheckPermBypass(new IHttpRequestResponse[]{messageInfo});
                    }
                });
                thread.start();
            }
        }
    }

    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            PermUI.LogEntry logEntry = log.get(row);
            originarequest.setMessage(logEntry.requestResponse.getRequest(),true);
            originaresponse.setMessage(logEntry.requestResponse.getResponse(),false);
            if (logEntry.lowRequestResponse == null || logEntry.noRequestResponse == null){
                lowerrequest.setMessage(null,false);
                lowerresponse.setMessage(null,false);
                norequest.setMessage(null,false);
                noresponse.setMessage(null,false);
                return;
            }
            lowerrequest.setMessage(logEntry.lowRequestResponse.getRequest(),true);
            lowerresponse.setMessage(logEntry.lowRequestResponse.getResponse(),false);
            norequest.setMessage(logEntry.noRequestResponse.getRequest(),true);
            noresponse.setMessage(logEntry.noRequestResponse.getResponse(),false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class LogEntry {
        private int id;
        private String method;
        private String url;
        private String originalength;
        private String lowlength;
        private String nolength;
        private String isSuccess;
        private IHttpRequestResponse requestResponse;
        private IHttpRequestResponse lowRequestResponse;
        private IHttpRequestResponse noRequestResponse;

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
}
