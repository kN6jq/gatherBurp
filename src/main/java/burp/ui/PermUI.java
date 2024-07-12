package burp.ui;

import burp.*;
import burp.bean.PermBean;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.Utils;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static burp.dao.PermDao.*;
import static burp.utils.Utils.getSuffix;

/**
 * @Author Xm17
 * @Date 2024-06-22 9:11
 */
public class PermUI implements UIHandler, IMessageEditorController, IHttpListener {
    private JPanel panel; // 主面板
    private static JTable permTable; // perm表格
    private IHttpRequestResponse currentlyDisplayedItem; // 当前显示的请求
    private JTabbedPane tabbedPanereqresp; // 请求tab
    private JPanel originPane; // 原始请求面板
    private JPanel lowpermPane; // 低权限请求面板
    private JPanel nopermPane; // 无权限请求面板
    private JCheckBox passiveScanCheckBox; // 被动扫描选择框
    private JCheckBox whiteDomainListCheckBox; // 白名单域名选择框
    private JTextArea whiteDomainListTextArea; // 白名单域名输入框
    private JButton saveWhiteDomainButton; // 保存白名单按钮
    private JButton saveAuthDataButton; // 保存认证数据按钮
    private JButton refreshButton; // 刷新按钮
    private JButton clearButton; // 清空数据按钮
    private JTextArea lowPermAuthTextArea; // 低权限认证请求信息输入框
    private JTextArea noPermAuthTextArea; // 无权限认证请求信息输入框
    private IMessageEditor originarequest;  // 原始请求
    private IMessageEditor originaresponse; // 原始响应
    private IMessageEditor lowpermrequest; // 低权限请求
    private IMessageEditor lowpermresponse; // 低权限响应
    private IMessageEditor nopermrequest; // 无权限请求
    private IMessageEditor nopermresponse; // 无权限响应
    private static final List<PermEntry> permlog = new ArrayList<>(); // permlog 用于存储请求
    private static final List<String> parameterList = new ArrayList<>(); // 参数列表
    private static final List<String> urlHashList = new ArrayList<>(); // url hash list
    private static boolean ispassiveScan; // 是否被动扫描
    private static boolean isWhiteDomainList; // 是否白名单

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (ispassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (permlog) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse}, false);
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
        return "PermAccess";
    }

    // 初始化数据
    private void setupData() {
        // 被动扫描选择框
        PermBean permBeanPassiveScanConfig = getPermListByType("permPassiveScan");
        if (permBeanPassiveScanConfig.getValue().equals("true")) {
            passiveScanCheckBox.setSelected(true);
            ispassiveScan = true;
        } else {
            passiveScanCheckBox.setSelected(false);
            ispassiveScan = false;
        }
        // 白名单域名选择框
        PermBean permBeanWhiteDomainConfig = getPermListByType("permWithDomain");
        if (permBeanWhiteDomainConfig.getValue().equals("true")) {
            whiteDomainListCheckBox.setSelected(true);
            isWhiteDomainList = true;
        } else {
            whiteDomainListCheckBox.setSelected(false);
            isWhiteDomainList = false;
        }
        // 白名单域名输入框
        List<PermBean> whiteDomain = getPermListsByType("domain");
        for (PermBean permBean : whiteDomain) {
            // 如果是最后一个，就不加换行符
            if (whiteDomain.indexOf(permBean) == whiteDomain.size() - 1) {
                whiteDomainListTextArea.setText(whiteDomainListTextArea.getText() + permBean.getValue());
                break;
            }
            whiteDomainListTextArea.setText(whiteDomainListTextArea.getText() + permBean.getValue() + "\n");
        }

        // permLowAuth输入框
        List<PermBean> permBeanLowAuth = getPermListsByType("permLowAuth");
        for (PermBean permBean : permBeanLowAuth) {
            // 如果是最后一个，就不加换行符
            if (permBeanLowAuth.indexOf(permBean) == permBeanLowAuth.size() - 1) {
                lowPermAuthTextArea.setText(lowPermAuthTextArea.getText() + permBean.getValue());
                break;
            }
            lowPermAuthTextArea.setText(lowPermAuthTextArea.getText() + permBean.getValue() + "\n");
        }

        // permNoAuth输入框
        List<PermBean> permBeanNoAuth = getPermListsByType("permNoAuth");
        for (PermBean permBean : permBeanNoAuth) {
            // 如果是最后一个，就不加换行符
            if (permBeanNoAuth.indexOf(permBean) == permBeanNoAuth.size() - 1) {
                noPermAuthTextArea.setText(noPermAuthTextArea.getText() + permBean.getValue());
                break;
            }
            noPermAuthTextArea.setText(noPermAuthTextArea.getText() + permBean.getValue() + "\n");
        }
        // 被动扫描选择框
        passiveScanCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (passiveScanCheckBox.isSelected()) {
                    ispassiveScan = true;
                    PermBean permBeanPassiveScanConfig = new PermBean("permPassiveScan", "true");
                    updatePerm(permBeanPassiveScanConfig);
                } else {
                    ispassiveScan = false;
                    PermBean permBeanPassiveScanConfig = new PermBean("permPassiveScan", "false");
                    updatePerm(permBeanPassiveScanConfig);
                }
            }
        });
        // 白名单域名选择框
        whiteDomainListCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (whiteDomainListCheckBox.isSelected()) {
                    isWhiteDomainList = true;
                    PermBean permBeanWhiteDomainConfig = new PermBean("permWithDomain", "true");
                    updatePerm(permBeanWhiteDomainConfig);
                } else {
                    isWhiteDomainList = false;
                    PermBean permBeanWhiteDomainConfig = new PermBean("permWithDomain", "false");
                    updatePerm(permBeanWhiteDomainConfig);
                }
            }
        });
        // 保存白名单
        saveWhiteDomainButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String whiteDomainList = whiteDomainListTextArea.getText();
                deletePerm("domain");
                if (whiteDomainList.contains("\n")) {
                    String[] split = whiteDomainList.split("\n");
                    for (String domain : split) {
                        PermBean permBean = new PermBean("domain", domain);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("domain", whiteDomainList);
                    savePerm(permBean);
                }
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        // 保存认证数据
        saveAuthDataButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String lowPermAuthText = lowPermAuthTextArea.getText();
                String noPermAuthText = noPermAuthTextArea.getText();
                deletePerm("permLowAuth");
                deletePerm("permNoAuth");
                if (lowPermAuthText.contains("\n")) {
                    String[] split = lowPermAuthText.split("\n");
                    for (String lowAuth : split) {
                        PermBean permBean = new PermBean("permLowAuth", lowAuth);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("permLowAuth", lowPermAuthText);
                    savePerm(permBean);
                }
                if (noPermAuthText.contains("\n")) {
                    String[] split = noPermAuthText.split("\n");
                    for (String noAuth : split) {
                        PermBean permBean = new PermBean("permNoAuth", noAuth);
                        savePerm(permBean);
                    }
                } else {
                    PermBean permBean = new PermBean("permNoAuth", noPermAuthText);
                    savePerm(permBean);
                }
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 刷新
        refreshButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                permTable.updateUI();
            }
        });
        // 清空
        clearButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                permlog.clear();
                originarequest.setMessage(new byte[0], true);
                originaresponse.setMessage(new byte[0], false);
                lowpermrequest.setMessage(new byte[0], false);
                lowpermresponse.setMessage(new byte[0], false);
                nopermrequest.setMessage(new byte[0], false);
                nopermresponse.setMessage(new byte[0], false);
                urlHashList.clear();
                permTable.updateUI();
            }
        });

    }

    // 初始化ui
    private void setupUI() {
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.setMaximumSize(panel.getPreferredSize()); // 设置最大尺寸等于首选尺寸，禁止自动调整
        JPanel mainsplitPane = new JPanel(new BorderLayout());

        // 左边的面板
        // 左边的面板上下分割,比例为7：3
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.7);
        leftSplitPane.setDividerLocation(0.7);

        // 将urlTable添加到leftSplitPane的上边
        JScrollPane leftScrollPane = new JScrollPane();
        permTable = new URLTable(new PermModel());
        permTable.setAutoCreateRowSorter(true);
        leftScrollPane.setViewportView(permTable);
        leftSplitPane.setTopComponent(leftScrollPane);

        // 左边的面板下部分对称分割，比例为5：5
        JSplitPane leftBottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        leftBottomSplitPane.setResizeWeight(0.5);
        leftBottomSplitPane.setDividerLocation(0.5);
        leftSplitPane.setBottomComponent(leftBottomSplitPane);

        // 请求tab
        tabbedPanereqresp = new JTabbedPane();
        // 添加原始请求面板
        originPane = new JPanel(new BorderLayout());
        final JSplitPane originPaneSplitPane = new JSplitPane();
        originPaneSplitPane.setDividerSize(1);
        originPaneSplitPane.setResizeWeight(0.5);
        originarequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        originaresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        originPaneSplitPane.setLeftComponent(originarequest.getComponent());
        originPaneSplitPane.setRightComponent(originaresponse.getComponent());
        originPane.add(originPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("原始请求包", originPane);
        // 添加低权限请求面板
        lowpermPane = new JPanel(new BorderLayout());
        final JSplitPane lowpermPaneSplitPane = new JSplitPane();
        lowpermPaneSplitPane.setDividerSize(1);
        lowpermPaneSplitPane.setResizeWeight(0.5);
        lowpermrequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        lowpermresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        lowpermPaneSplitPane.setLeftComponent(lowpermrequest.getComponent());
        lowpermPaneSplitPane.setRightComponent(lowpermresponse.getComponent());
        lowpermPane.add(lowpermPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("低权限请求包", lowpermPane);
        // 添加无权限请求面板
        nopermPane = new JPanel(new BorderLayout());
        final JSplitPane nopermPaneSplitPane = new JSplitPane();
        nopermPaneSplitPane.setDividerSize(1);
        nopermPaneSplitPane.setResizeWeight(0.5);
        nopermrequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        nopermresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        nopermPaneSplitPane.setLeftComponent(nopermrequest.getComponent());
        nopermPaneSplitPane.setRightComponent(nopermresponse.getComponent());
        nopermPane.add(nopermPaneSplitPane, BorderLayout.CENTER);
        tabbedPanereqresp.addTab("无权限请求包", nopermPane);

        // 请求tab添加到leftBottomSplitPane的左边
        leftBottomSplitPane.setLeftComponent(tabbedPanereqresp);

        // 将leftSplitPane添加到mainsplitPane的左边
        mainsplitPane.add(leftSplitPane, BorderLayout.CENTER);

        JPanel rightSplitPane = new JPanel(new GridBagLayout());
        // 右边的上面
        // 被动扫描选择框
        passiveScanCheckBox = new JCheckBox("被动扫描");
        // 白名单域名选择框
        whiteDomainListCheckBox = new JCheckBox("白名单域名");
        // 白名单域名Label
        JLabel whiteListLabel = new JLabel("白名单域名");
        // 白名单域名输入框
        whiteDomainListTextArea = new JTextArea(5,10);
        whiteDomainListTextArea.setLineWrap(false); // 自动换行
        whiteDomainListTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteDomainListTextArea);
        // 保存白名单按钮
        saveWhiteDomainButton = new JButton("保存白名单");
        // 保存认证数据按钮
        saveAuthDataButton = new JButton("保存认证数据");
        // 刷新按钮
        refreshButton = new JButton("刷新表格");
        // 清空数据按钮
        clearButton = new JButton("清空表格");

        // 右边的下部分
        // 低权限认证请求信息Label
        JLabel lowPermAuthLabel = new JLabel("低权限认证请求信息");
        // 低权限认证请求信息输入框
        lowPermAuthTextArea = new JTextArea(5,10);
        lowPermAuthTextArea.setLineWrap(false); // 自动换行
        lowPermAuthTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane lowPermAuthTextAreascrollPane = new JScrollPane(lowPermAuthTextArea);

        // 无权限认证请求信息Label
        JLabel noPermAuthLabel = new JLabel("无权限认证请求信息(输入请求头信息，不输入请求体信息)");
        // 无权限认证请求信息输入框
        noPermAuthTextArea = new JTextArea(5,10);
        noPermAuthTextArea.setLineWrap(false); // 自动换行
        noPermAuthTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane noPermAuthTextAreascrollPane = new JScrollPane(noPermAuthTextArea);

        // passiveScanCheckBox和whiteDomainListCheckBox在第一行
        rightSplitPane.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightSplitPane.add(whiteDomainListCheckBox, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // saveWhiteListButton和saveAuthDataButton在第二行
        rightSplitPane.add(saveWhiteDomainButton, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightSplitPane.add(saveAuthDataButton, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // whiteListLabel在第三行
        rightSplitPane.add(whiteListLabel, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // whiteListTextArea在第四行
        rightSplitPane.add(whiteListTextAreascrollPane, new GridBagConstraintsHelper(0, 3, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        // refreshButton和clearButton在第五行
        rightSplitPane.add(refreshButton, new GridBagConstraintsHelper(0, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightSplitPane.add(clearButton, new GridBagConstraintsHelper(1, 4, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // lowPermAuthLabel在第六行
        rightSplitPane.add(lowPermAuthLabel, new GridBagConstraintsHelper(0, 5, 2, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // lowPermAuthTextArea在第七行
        rightSplitPane.add(lowPermAuthTextAreascrollPane, new GridBagConstraintsHelper(0, 6, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        // noPermAuthLabel在第八行
        rightSplitPane.add(noPermAuthLabel, new GridBagConstraintsHelper(0, 7, 2, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // noPermAuthTextArea在第九行
        rightSplitPane.add(noPermAuthTextAreascrollPane, new GridBagConstraintsHelper(0, 8, 2, 1).setInsets(5).setIpad(0, 0).setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        // 将rightSplitPane添加到mainsplitPane的右边
        mainsplitPane.add(rightSplitPane, BorderLayout.EAST);
        panel.add(mainsplitPane, BorderLayout.CENTER);
    }

    // url hash list
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

    // 核心检测方法
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        String method = analyzeRequest.getMethod();
        URL rdurlURL = analyzeRequest.getUrl();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();

        // 如果method不是get或者post方式直接返回
        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }
        String rdurl = Utils.getUrlWithoutFilename(rdurlURL);
        // 如果是右键发送的则不进行去重
        if (!isSend) {
            for (IParameter paraList : paraLists) {
                String paraName = paraList.getName();
                parameterList.add(paraName);
            }
            // 检测url hash 去重
            if (!checkUrlHash(method + rdurl + parameterList)) {
                return;
            }
        } else {
            isWhiteDomainList = false;
        }


        // 静态资源不检测
        List<String> suffix = getSuffix();
        if (!suffix.isEmpty()) {
            for (String s : suffix) {
                if (url.endsWith(s) || url.contains(s)) {
                    return;
                }
            }
        }
        // 开启白名单域名检测
        if (isWhiteDomainList) {
            List<PermBean> permBeanWhiteDomain = getPermListsByType("domain");
            if (permBeanWhiteDomain.isEmpty()) {
                JOptionPane.showMessageDialog(null, "请先填写白名单域名", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            boolean containsWhiteDomain = false;
            for (PermBean permBean : permBeanWhiteDomain) {
                if (url.contains(permBean.getValue())) {
                    containsWhiteDomain = true;
                    break; // 如果包含白名单域名，则跳出循环
                }
            }
            if (!containsWhiteDomain) {
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
        // 如果原始请求的响应体为空，则不进行后续操作
        if (responseBody == null) {
            return;
        }
        // 获取低权限数据去构造请求
        List<String> lowheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<PermBean> permBeanLowAuth = getPermListsByType("permLowAuth");
        for (PermBean permBean : permBeanLowAuth) {
            String lowAuthText = permBean.getValue();
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
        List<PermBean> permBeanNoAuth = getPermListsByType("permNoAuth");
        List<String> updatedHeaders = new ArrayList<>();

        for (String header : noheaders) {
            boolean shouldKeep = true;
            for (PermBean permBean : permBeanNoAuth) {
                String noAuthText = permBean.getValue();
                if (header.contains(noAuthText)) {
                    shouldKeep = false;
                    break;
                }
            }
            if (shouldKeep) {
                updatedHeaders.add(header);
            }
        }
        // 更新原始的noheaders列表
        noheaders.clear();
        noheaders.addAll(updatedHeaders);

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
            isSuccess = "可能存在";
        } else {
            isSuccess = "不存在";
        }

        add(method, url, originallength, lowlength, nolength, isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse);

    }

    private static void add(String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse baseRequestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
        synchronized (permlog) {
            int id = permlog.size();
            permlog.add(new PermEntry(id, method, url, originalength, lowlength, nolength, isSuccess, baseRequestResponse, lowRequestResponse, noRequestResponse));
            permTable.updateUI();
        }
    }

    // perm 模型
    static class PermModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return permlog.size();
        }

        @Override
        public int getColumnCount() {
            return 7;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return permlog.get(rowIndex).id;
                case 1:
                    return permlog.get(rowIndex).method;
                case 2:
                    return permlog.get(rowIndex).url;
                case 3:
                    return permlog.get(rowIndex).originalength;
                case 4:
                    return permlog.get(rowIndex).lowlength;
                case 5:
                    return permlog.get(rowIndex).nolength;
                case 6:
                    return permlog.get(rowIndex).isSuccess;
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

    // perm 实体
    private static class PermEntry {
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

        public PermEntry(int id, String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse requestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
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

    // perm 表格
    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            PermEntry logEntry = permlog.get(row);
            originarequest.setMessage(logEntry.requestResponse.getRequest(), true);
            originaresponse.setMessage(logEntry.requestResponse.getResponse(), false);
            if (logEntry.lowRequestResponse == null || logEntry.noRequestResponse == null) {
                lowpermrequest.setMessage(null, false);
                lowpermresponse.setMessage(null, false);
                nopermrequest.setMessage(null, false);
                nopermresponse.setMessage(null, false);
                return;
            }
            lowpermrequest.setMessage(logEntry.lowRequestResponse.getRequest(), true);
            lowpermresponse.setMessage(logEntry.lowRequestResponse.getResponse(), false);
            nopermrequest.setMessage(logEntry.noRequestResponse.getRequest(), true);
            nopermresponse.setMessage(logEntry.noRequestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

}
