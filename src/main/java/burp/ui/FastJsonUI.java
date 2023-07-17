package burp.ui;

import burp.*;
import burp.bean.Config;
import burp.bean.Fastjson;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import static burp.dao.ConfigDAO.getValueByModuleAndType;
import static burp.dao.FastjsonDAO.*;
import static burp.utils.Utils.*;


public class FastJsonUI extends AbstractTableModel implements UIHandler, IMessageEditorController {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private static final List<LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;

    @Override
    public void init() {

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        JPanel jp=new JPanel(new BorderLayout());
        JSplitPane mSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); // 主分隔面板

        JTable urlTable = new URLTable(FastJsonUI.this);
        JScrollPane jScrollPane = new JScrollPane(urlTable); // 滚动条

        JSplitPane xjSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT); // 请求与响应界面的分隔面板

        JTabbedPane ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(FastJsonUI.this, true);
        ltable.addTab("Request", HRequestTextEditor.getComponent());
        JTabbedPane rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(FastJsonUI.this, false);
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
        JButton deleteAllbutton = new JButton("删除全部");
        deleteAllbutton.addActionListener(new AbstractAction() {
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
        buttonPanel.add(deleteAllbutton);
        buttonSplitPane.setTopComponent(buttonPanel);
        jp.add(buttonSplitPane, BorderLayout.NORTH);


        jp.add(mSplitPane);
        return jp;

    }


    public void CheckDnslog(IHttpRequestResponse[] responses){
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String res = "dnslog检测";
        try {
            List<Fastjson> payloads = getFastjsonListByDnsLog();
            if (payloads.size() == 0){
                JOptionPane.showMessageDialog(null, "请先添加dnslog payload", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            Config dnslogKey = getValueByModuleAndType("config", "dnslog");
            String dnslog = dnslogKey.getValue();
            if (dnslog.equals("")){
                JOptionPane.showMessageDialog(null, "请先设置dnslog 地址", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<Fastjson> iterator = payloads.iterator();
            while (iterator.hasNext()){
                Fastjson fastjson = iterator.next();
                String fastjsonDnslog = fastjson.getUrl();
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslog);
                byte[] bytePayload = Utils.helpers.stringToBytes(fuzzPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod,url,statusCode,res,resp);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

    }

    public void CheckEchoVul(IHttpRequestResponse[] responses){
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        try {
            List<Fastjson> payloads = getFastjsonListByEchoVul();
            if (payloads.size() == 0){
                JOptionPane.showMessageDialog(null, "请先添加echo payload", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            // 弹出一个输入框，用于获取用户输入的dnslog地址
            String defaultValue = "whoami";
            String echoVul = (String) JOptionPane.showInputDialog(null, "请输入echo 命令", "提示", JOptionPane.PLAIN_MESSAGE, null, null, defaultValue);
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<Fastjson> iterator = payloads.iterator();
            headers.add("Accept-Cache: " + echoVul);
            while (iterator.hasNext()){
                Fastjson fastjson = iterator.next();
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
                    add(extensionMethod,url,statusCode,"echo命令检测成功",resp);
                } else {
                    add(extensionMethod,url,statusCode,"echo命令检测失败",resp);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void CheckJNDIVul(IHttpRequestResponse[] responses){
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String extensionMethod = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<String> headers = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        try {
            List<Fastjson> payloads = getFastjsonListByJNDI();
            if (payloads.size() == 0){
                JOptionPane.showMessageDialog(null, "请先添加jndi payload", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String jndiStr = "";
            String defaultValue = "IP"; // 设置默认值
            String[] options = { "DNS", "IP" }; // 单选框选项
            String selectedValue = (String) JOptionPane.showInputDialog(null, "请选择类型", "提示",
                    JOptionPane.PLAIN_MESSAGE, null, options, defaultValue);
            if (Objects.equals(selectedValue, "DNS")){
                Config config = getValueByModuleAndType("config", "dnslog");
                String dnslog = config.getValue();
                if (!dnslog.equals("")){
                    jndiStr = dnslog;
                }else {
                    JOptionPane.showMessageDialog(null, "请先在Config面板设置dnslog 地址", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }else if (Objects.equals(selectedValue, "IP")){
                Config config = getValueByModuleAndType("config", "ip");
                String ip = config.getValue();
                if (!ip.equals("")) {
                    jndiStr = ip;
                }else {
                    JOptionPane.showMessageDialog(null, "请先在Config面板设置IP地址", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }

            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<Fastjson> iterator = payloads.iterator();
            while (iterator.hasNext()){
                String dnslogKey = "";

                Fastjson fastjson = iterator.next();
                String fastjsonJNDI = fastjson.getUrl();
                String id = String.valueOf(fastjson.getId());
                if (selectedValue.equals("DNS")){
                    dnslogKey = "ldap://"+id+"."+jndiStr;
                }else {
                    dnslogKey = "ldap://"+jndiStr+"/"+id;
                }
                String fuzzPayload = fastjsonJNDI.replace("FUZZ", dnslogKey);
                byte[] bytePayload = Utils.helpers.stringToBytes(fuzzPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod,url,statusCode,"jndi检测完成,请查看dnslog服务器",resp);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }


    public int add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log){
            int id = log.size();
            log.add(
                new LogEntry(
                    id,
                    extensionMethod,
                    url,
                    status,
                    res,
                    baseRequestResponse
                )
            );
         fireTableRowsInserted(id,id);
         fireTableDataChanged();
         return id;
        }
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
        LogEntry logEntry = log.get(rowIndex);
        switch (columnIndex){
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
        switch (column){
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
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public String getTabName() {
        return "fastjson";
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







    private static class LogEntry
    {
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

