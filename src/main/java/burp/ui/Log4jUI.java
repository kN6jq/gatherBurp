package burp.ui;

import burp.*;
import burp.bean.Log4jBean;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.Log4jDao.*;

/**
 * @Author Xm17
 * @Date 2024-06-22 12:45
 */
public class Log4jUI implements UIHandler, IMessageEditorController, IHttpListener {
    private JPanel panel; // 主面板
    private static JTable log4jtable; // log4j表格
    private JCheckBox passiveScanCheckBox; // 被动扫描选择框
    private JCheckBox originalValueCheckBox; // 原始payload值选择框
    private JCheckBox checkHeaderCheckBox; // 检测header选择框
    private JCheckBox isDnsOrIpCheckBox; // 是否是dns或者ip选择框
    private JCheckBox checkWhiteListCheckBox; // 白名单域名检测选择框
    private JCheckBox checkParmamCheckBox; // 检测参数选择框
    private JButton saveWhiteListButton; // 保存白名单域名按钮
    private JButton saveHeaderListButton; // 保存header按钮
    private JButton savePayloadButton; // 保存log4j payload按钮
    private JButton refreshTableButton; // 刷新表格按钮
    private JButton clearTableButton;// 清空表格按钮
    private JTextArea whiteListTextArea; // 白名单域名输入框
    private JTextArea headerTextArea; // header输入框
    private JTextArea payloadTextArea; // payload输入框
    private JTabbedPane tabbedPanereq; // 请求tab
    private JTabbedPane tabbedPaneresp; // 响应tab
    private JScrollPane urltablescrollpane; // url table scroll pane
    private IHttpRequestResponse currentlyDisplayedItem; // currently displayed item
    private IMessageEditor HRequestTextEditor; // request editor
    private IMessageEditor HResponseTextEditor; // response editor
    private static final List<Log4jEntry> log4jlog = new ArrayList<>();
    private static final List<String> parameterList = new ArrayList<>(); // 参数列表
    private static final List<String> urlHashList = new ArrayList<>(); // url hash list
    private static boolean isPassiveScan; // 是否是被动扫描
    private static boolean isOriginalValue; // 是否删除原始值
    private static boolean isCheckHeader; // 是否检测header
    private static boolean isCheckParam; // 是否检测参数
    private static boolean isDnsOrIp; // 是否是dns或者ip
    private static boolean isCheckWhiteList; // 是否检测白名单
    private static Set<String> log4jPayload = new LinkedHashSet<>(); // 存储log4j payload
    private static List<String> payloadList = new ArrayList<>(); // payload列表
    private static List<String> domainList = new ArrayList<>(); // 白名单域名
    private static List<String> headerList = new ArrayList<>(); // header列表
    public static String dns;
    public static String ip;
    private static final Lock lock = new ReentrantLock();



    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isPassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (log4jlog) {
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

        // 存储白名单域名
        List<Log4jBean> domain = getLog4jListsByType("domain");
        // 将domain转为List<String>
        for (Log4jBean log4jBean : domain) {
            domainList.add(log4jBean.getValue());
        }

        dns = getConfig("config", "dnslog").getValue();
        ip = getConfig("config", "ip").getValue();

        setupUI();
        setupData();
    }

    // 初始化数据
    private void setupData() {
        //从数据库中获取是否是被动扫描
        Log4jBean log4jPassiveScanConfig = getLog4jListByType("log4jPassiveScan");
        if (log4jPassiveScanConfig.getValue().equals("true")){
            isPassiveScan = true;
            passiveScanCheckBox.setSelected(true);
        }else{
            isPassiveScan = false;
            passiveScanCheckBox.setSelected(false);
        }
        // 从数据库中获取是否为原始值
        Log4jBean log4jOrginValueConfig = getLog4jListByType("log4jOrginValue");
        if (log4jOrginValueConfig.getValue().equals("true")) {
            isOriginalValue = true;
            originalValueCheckBox.setSelected(true);
        }else {
            isOriginalValue = false;
            originalValueCheckBox.setSelected(false);
        }
        // 从数据库中获取是否检测header
        Log4jBean log4jCheckHeaderConfig = getLog4jListByType("log4jCheckHeader");
        if (log4jCheckHeaderConfig.getValue().equals("true")) {
            isCheckHeader = true;
            checkHeaderCheckBox.setSelected(true);
        }else {
            isCheckHeader = false;
            checkHeaderCheckBox.setSelected(false);
        }

        // 从数据库中获取是否检测参数
        Log4jBean log4jCheckParamConfig = getLog4jListByType("log4jCheckParam");
        if (log4jCheckParamConfig.getValue().equals("true")) {
            isCheckParam = true;
            checkParmamCheckBox.setSelected(true);
        }else {
            isCheckParam = false;
            checkParmamCheckBox.setSelected(false);
        }

        // 从数据库中获取是否是dns或者ip
        Log4jBean log4jIsDnsOrIpConfig = getLog4jListByType("log4jIsDnsOrIp");
        if (log4jIsDnsOrIpConfig.getValue().equals("true")) {
            isDnsOrIp = true;
            isDnsOrIpCheckBox.setSelected(true);
            isDnsOrIpCheckBox.setText("dns");
        } else {
            isDnsOrIp = false;
            isDnsOrIpCheckBox.setSelected(false);
            isDnsOrIpCheckBox.setText("ip");
        }

        // 从数据库中获取是否检测白名单
        Log4jBean log4jCheckWhiteListConfig = getLog4jListByType("log4jCheckWhiteList");
        if (log4jCheckWhiteListConfig.getValue().equals("true")) {
            isCheckWhiteList = true;
            checkWhiteListCheckBox.setSelected(true);
        } else {
            isCheckWhiteList = false;
            checkWhiteListCheckBox.setSelected(false);
        }
        // 被动扫描选择框
        passiveScanCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (passiveScanCheckBox.isSelected()) {
                    isPassiveScan = true;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jPassiveScan");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isPassiveScan = false;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jPassiveScan");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });
        // 原始payload值选择框
        originalValueCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (originalValueCheckBox.isSelected()) {
                    isOriginalValue = true;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jOrginValue");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isOriginalValue = false;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jOrginValue");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });
        // 检测header选择框
        checkHeaderCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkHeaderCheckBox.isSelected()) {
                    isCheckHeader = true;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckHeader");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isCheckHeader = false;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckHeader");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });
        // 检测参数选择框
        checkParmamCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkParmamCheckBox.isSelected()) {
                    isCheckParam = true;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckParam");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isCheckParam = false;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckParam");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });
        // 是否是dns或者ip选择框
        isDnsOrIpCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dns = getConfig("config", "dnslog").getValue();
                ip = getConfig("config", "ip").getValue();
                if (isDnsOrIpCheckBox.isSelected()) {
                    isDnsOrIp = true;
                    isDnsOrIpCheckBox.setText("dns");
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jIsDnsOrIp");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isDnsOrIp = false;
                    isDnsOrIpCheckBox.setText("ip");
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jIsDnsOrIp");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });

        // 初始化白名单输入框
        List<Log4jBean> domain = getLog4jListsByType("domain");
        for (Log4jBean log4jBean : domain) {
            whiteListTextArea.setText(whiteListTextArea.getText() + log4jBean.getValue() + "\n");
            domainList.add(log4jBean.getValue());
        }
        // 初始化header输入框
        List<Log4jBean> header = getLog4jListsByType("header");
        for (Log4jBean log4jBean : header) {
            headerTextArea.setText(headerTextArea.getText() + log4jBean.getValue() + "\n");
            headerList.add(log4jBean.getValue());
        }
        // 初始化payload输入框
        List<Log4jBean> payload = getLog4jListsByType("payload");
        for (Log4jBean log4jBean : payload) {
            payloadTextArea.setText(payloadTextArea.getText() + log4jBean.getValue() + "\n");
            payloadList.add(log4jBean.getValue());
        }

        // 检测白名单选择框
        checkWhiteListCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkWhiteListCheckBox.isSelected()) {
                    isCheckWhiteList = true;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckWhiteList");
                    log4jBean.setValue("true");
                    updateLog4j(log4jBean);
                } else {
                    isCheckWhiteList = false;
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setType("log4jCheckWhiteList");
                    log4jBean.setValue("false");
                    updateLog4j(log4jBean);
                }
            }
        });
        // 保存白名单域名按钮
        saveWhiteListButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String whiteListTextAreaText = whiteListTextArea.getText();
                deleteLog4jByType("domain");
                // 如果包含换行符，就分割成多个domain
                if (whiteListTextAreaText.contains("\n")) {
                    String[] split = whiteListTextAreaText.split("\n");
                    for (String s : split) {
                        Log4jBean log4jBean = new Log4jBean("domain", s);
                        saveLog4j(log4jBean);
                    }
                } else {
                    Log4jBean log4jBean = new Log4jBean("domain", whiteListTextAreaText);
                    saveLog4j(log4jBean);
                }
                // 存储白名单域名
                List<Log4jBean> domain = getLog4jListsByType("domain");
                // 将domain转为List<String>
                for (Log4jBean log4jBean : domain) {
                    domainList.add(log4jBean.getValue());
                }
                whiteListTextArea.updateUI();
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        // 保存header按钮
        saveHeaderListButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String headerTextAreaText = headerTextArea.getText();
                deleteLog4jByType("header");
                String[] split = headerTextAreaText.split("\n");
                for (String s : split) {
                    Log4jBean log4jBean = new Log4jBean("header", s);
                    saveLog4j(log4jBean);
                }
                List<Log4jBean> header = getLog4jListsByType("header");
                for (Log4jBean log4jBean : header) {
                    headerList.add(log4jBean.getValue());
                }
                headerTextArea.updateUI();
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        // 保存payload按钮
        savePayloadButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String payloadTextAreaText = payloadTextArea.getText();
                deleteLog4jByType("payload");
                String[] split = payloadTextAreaText.split("\n");
                for (String s : split) {
                    Log4jBean log4jBean = new Log4jBean("payload", s);
                    saveLog4j(log4jBean);
                }
                List<Log4jBean> payload = getLog4jListsByType("payload");
                for (Log4jBean log4jBean : payload) {
                    payloadList.add(log4jBean.getValue());
                }


                payloadTextArea.updateUI();
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        // 刷新表格
        refreshTableButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log4jtable.updateUI();
            }
        });

        // 清空表格
        clearTableButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log4jlog.clear();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
                urlHashList.clear();
                log4jtable.updateUI();
            }
        });

    }

    // 初始化UI
    private void setupUI() {
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout());

        JPanel splitPane = new JPanel(new BorderLayout());
        // 左边的面板
        // 左边的上下按7:3分割
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.7);
        leftSplitPane.setDividerLocation(0.7);
        // 左边的上面是表格
        urltablescrollpane = new JScrollPane();
        log4jtable = new URLTable(new Log4jModel());
        urltablescrollpane.setViewportView(log4jtable);
        leftSplitPane.setTopComponent(urltablescrollpane);



        // 左边的下面是消息编辑器
        tabbedPanereq = new JTabbedPane();
        tabbedPaneresp = new JTabbedPane();
        HRequestTextEditor = Utils.callbacks.createMessageEditor(this, false);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(this, false);
        tabbedPanereq.addTab("Request", HRequestTextEditor.getComponent());
        tabbedPaneresp.addTab("Response", HResponseTextEditor.getComponent());
        JSplitPane leftDownSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        leftDownSplitPane.setResizeWeight(0.5);
        leftDownSplitPane.setDividerLocation(0.5);
        leftDownSplitPane.setLeftComponent(tabbedPanereq);
        leftDownSplitPane.setRightComponent(tabbedPaneresp);
        leftSplitPane.setBottomComponent(leftDownSplitPane);


        // 右边的面板
        // 右边的上下按7:3分割
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setDividerLocation(0.7);


        // 右边的上部分
        // 添加被动扫描选择框
        passiveScanCheckBox = new JCheckBox("被动扫描");
        // 添加删除原始值选择框
        originalValueCheckBox = new JCheckBox("原始payload");
        // 添加检测cookie选择框
        checkParmamCheckBox = new JCheckBox("检测参数");
        // 添加检测header选择框
        checkHeaderCheckBox = new JCheckBox("检测header");
        // 添加白名单域名检测选择框
        checkWhiteListCheckBox = new JCheckBox("白名单域名检测");
        isDnsOrIpCheckBox = new JCheckBox("dns");
        // 白名单域名保存按钮
        saveWhiteListButton = new JButton("保存白名单域名");
        // 保存header按钮
        saveHeaderListButton = new JButton("保存header");
        // 白名单域名输入框列表
        whiteListTextArea = new JTextArea(5,10);
        whiteListTextArea.setLineWrap(false); // 自动换行
        whiteListTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteListTextArea);

        // header检测数据框列表
        headerTextArea = new JTextArea(5,10);
        headerTextArea.setLineWrap(false); // 自动换行
        headerTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane headerTextAreascrollPane = new JScrollPane(headerTextArea);
        // 刷新表格按钮
        refreshTableButton = new JButton("刷新表格");
        // 清空表格按钮
        clearTableButton = new JButton("清空表格");
        // 白名单域名label
        JLabel whiteDomainListLabel = new JLabel("白名单域名");
        // 检测header label
        JLabel headerLabel = new JLabel("header检测列表");


        // 添加到右边的上部分
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new GridBagLayout());
        rightTopPanel.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(originalValueCheckBox, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkHeaderCheckBox, new GridBagConstraintsHelper(2, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkParmamCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkWhiteListCheckBox, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(isDnsOrIpCheckBox, new GridBagConstraintsHelper(2, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveWhiteListButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveHeaderListButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteDomainListLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteListTextAreascrollPane, new GridBagConstraintsHelper(0, 4, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(headerLabel, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(headerTextAreascrollPane, new GridBagConstraintsHelper(0, 6, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(refreshTableButton, new GridBagConstraintsHelper(0, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(clearTableButton, new GridBagConstraintsHelper(1, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        rightSplitPane.setTopComponent(rightTopPanel);


        // 右边的下部分左边
        // log4j payload label
        JLabel PayloadLabel = new JLabel("payload 列表");
        // log4j payload输入框
        // log4j payload保存按钮
        payloadTextArea = new JTextArea(5,10);
        payloadTextArea.setLineWrap(false); // 自动换行
        payloadTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane payloadTextAreascrollPane = new JScrollPane(payloadTextArea);
        savePayloadButton = new JButton("保存payload");
        JPanel rightDownLeftPanel = new JPanel();
        rightDownLeftPanel.setLayout(new GridBagLayout());
        rightDownLeftPanel.add(PayloadLabel, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(payloadTextAreascrollPane, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightDownLeftPanel.add(savePayloadButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));


        // 左右分割面板添加rightDownLeftPanel和rightDownRightPanel
        JPanel rightDownPanel = new JPanel(new BorderLayout());
        rightDownPanel.add(rightDownLeftPanel, BorderLayout.CENTER);
        rightSplitPane.setBottomComponent(rightDownPanel);

        // 添加到splitPane
        splitPane.add(leftSplitPane, BorderLayout.CENTER);
        splitPane.add(rightSplitPane, BorderLayout.EAST);
        panel.add(splitPane, BorderLayout.CENTER);
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "Log4jScan";
    }
    // 添加数据
    public static void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log4jlog) {
            int id = log4jlog.size();
            log4jlog.add(new Log4jEntry(id, extensionMethod, url, status, res, baseRequestResponse));
            log4jtable.updateUI();
        }

    }
    // 检测url是否重复
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
    // 获取请求包的tag
    private static String getReqTag(IHttpRequestResponse baseRequestResponse, IRequestInfo req, String type) {
        List<String> requestHeader = req.getHeaders();
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。
        //第一行请求包含请求方法、请求uri、http版本
        String firstrequestHeader = requestHeader.get(0);
        String[] firstheaders = firstrequestHeader.split(" ");
        String uri = firstheaders[1].split("\\?")[0].replace("/", ".");
        if (firstheaders[1].split("\\?")[0].replace("/", ".").length() > 25) {
            uri = uri.substring(0, 25);
            if (uri.endsWith(".")) {
                uri = uri.substring(0, uri.length() - 1);
            }
        }
        if (uri.endsWith(".")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        if (type.equals("dns")) {
            return firstheaders[0].trim() + "." + host + uri + ".";
        } else {
            return firstheaders[0].trim() + "." + host + uri;
        }
    }

    // 检测核心方法
    public static void Check(IHttpRequestResponse[] messageInfo, boolean isSend) {
        lock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = messageInfo[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String method = analyzeRequest.getMethod();
            String host = baseRequestResponse.getHttpService().getHost();
            URL rdurlURL = analyzeRequest.getUrl();
            String url = analyzeRequest.getUrl().toString();
            List<IParameter> paraLists = analyzeRequest.getParameters();

            // 如果method不是get或者post方式直接返回
            if (!method.equals("GET") && !method.equals("POST")) {
                return;
            }
            // url 中匹配为静态资源
            if (Utils.isUrlBlackListSuffix(url)){
                return;
            }
            // 如果没有开启检测参数和检测header 并且参数没有值 直接返回
            if (!isCheckParam && !isCheckHeader) {
                return;
            }

            // 判断参数类型，不符合的直接跳过检测
            boolean ruleHit = true; // 默认设置为true，表示命中规则
            for (IParameter para : paraLists) {
                if ((para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON)
                        || isCheckHeader) {
                    ruleHit = false; // 如果有 URL、BODY、JSON 参数或者开启了header 检测，则不命中规则
                    break;
                }
            }
            if (ruleHit) {
                return; // 如果命中规则，则直接返回
            }


            String rdurl = Utils.getUrlWithoutFilename(rdurlURL);
            // 如果不是手动发送则需要进行url去重
            if (!isSend) {
                // 对url进行hash去重
                for (IParameter paraList : paraLists) {
                    String paraName = paraList.getName();
                    parameterList.add(paraName);
                }
                if (!checkUrlHash(method + rdurl + parameterList)) {
                    return;
                }
            }else {
                isCheckWhiteList = false;
            }

            if (isCheckWhiteList) {
                // 如果未匹配到 直接返回
                if (!Utils.isMatchDomainName(host,domainList)){
                    return;
                }
            }
            // 加入payload前先清空列表
            log4jPayload.clear();
            // 将数据库中的payload加入到列表
            for (String log4j : payloadList) {
                if (isOriginalValue) {
                    log4jPayload.add(log4j);
                } else {
                    if (log4j.contains("dnslog-url")) {
                        if (isDnsOrIp) {
                            String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "dns");
                            log4jPayload.add(log4j.replace("dnslog-url", logPrefix + dns));
                        } else {
                            String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "ip");
                            log4jPayload.add(log4j.replace("dnslog-url", ip + "/" + logPrefix));
                        }
                    } else {
                        log4jPayload.add(log4j);
                    }
                }
            }

            // 检测参数
            if (isCheckParam) {
                for (IParameter para : paraLists) {
                    if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON) {
                        String paraName = para.getName();
                        String paraValue = para.getValue();
                        // 判断参数是否在url中
                        if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                            for (String logPayload : log4jPayload) {
                                // 如果是在get请求中，需要对payload进行url编码
                                if (para.getType() == PARAM_URL) {
                                    logPayload = Utils.UrlEncode(logPayload);
                                }
                                IParameter iParameter = Utils.helpers.buildParameter(paraName, logPayload, para.getType());
                                byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                                byte[] log4jresponseBody = newRequestResponse.getResponse();
                                String ParamLength = "";
                                String ParamstatusCode = String.valueOf(analyzeResponse.getStatusCode());
                                if (log4jresponseBody != null) {
                                    // 判断有无Content-Length字段
                                    IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(log4jresponseBody);
                                    List<String> log4jHeaders = ReqResponse.getHeaders();
                                    for (String header : log4jHeaders) {
                                        if (header.contains("Content-Length")) {
                                            ParamLength = header.split(":")[1].trim();
                                            break;
                                        }
                                    }
                                }
                                if (ParamLength.isEmpty()) {
                                    assert log4jresponseBody != null;
                                    ParamLength = String.valueOf(log4jresponseBody.length);
                                }
                                add(method, url, ParamstatusCode, ParamLength, newRequestResponse);
                            }

                        }
                        // 判断参数是否在json中
                        if (para.getType() == PARAM_JSON) {
                            for (String logPayload : log4jPayload) {
                                String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                                Map<String, Object> request_json = JSON.parseObject(request_data);
                                List<Object> objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(logPayload), 0);
                                String json = "";
                                for (Object o : objectList) {
                                    json = JSON.toJSONString(o);
                                }
                                byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, json.getBytes());
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                                byte[] log4jresponseBody = newRequestResponse.getResponse();
                                String ParamLength = "";
                                String ParamstatusCode = String.valueOf(analyzeResponse.getStatusCode());
                                if (log4jresponseBody != null) {
                                    // 判断有无Content-Length字段
                                    IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(log4jresponseBody);
                                    List<String> log4jHeaders = ReqResponse.getHeaders();
                                    for (String header : log4jHeaders) {
                                        if (header.contains("Content-Length")) {
                                            ParamLength = header.split(":")[1].trim();
                                            break;
                                        }
                                    }
                                }
                                if (ParamLength.isEmpty()) {
                                    assert log4jresponseBody != null;
                                    ParamLength = String.valueOf(log4jresponseBody.length);
                                }
                                add(method, url, ParamstatusCode, ParamLength, newRequestResponse);

                            }
                            break;
                        }
                    }
                }
            }


            // 检测header
            if (isCheckHeader) {
                byte[] byte_Request = baseRequestResponse.getRequest();
                int bodyOffset = analyzeRequest.getBodyOffset();
                int len = byte_Request.length;
                byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
                for (String logPayload : log4jPayload) {
                    List<String> reqheaders2 = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
                    List<String> newReqheaders = new ArrayList<>();
                    Iterator<String> iterator = reqheaders2.iterator();
                    while (iterator.hasNext()) {
                        String reqheader = iterator.next();
                        for (String header : headerList) {
                            if (reqheader.contains(header)) {
                                iterator.remove();
                                String newHeader = header + ": " + logPayload;
                                if (!newReqheaders.contains(newHeader)) {
                                    newReqheaders.add(newHeader);
                                }
                            }
                        }
                    }
                    for (String header : headerList) {
                        String newHeader = header + ": " + logPayload;
//                    if (!reqheaders2.contains(header) && !newReqheaders.contains(newHeader)) {
//                        newReqheaders.add(newHeader);
//                    }
                        newReqheaders.add(newHeader);
                    }

                    reqheaders2.addAll(newReqheaders);
                    byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders2, body);
                    IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
                    byte[] responseBody = originalRequestResponse.getResponse();

                    String originallength = "";
                    String statusCode = "";
                    if (responseBody != null) {
                        IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
                        List<String> headers = originalReqResponse.getHeaders();
                        statusCode = String.valueOf(originalReqResponse.getStatusCode());
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
                    add(method, url, statusCode, originallength, originalRequestResponse);
                }
            }
        }finally {
            lock.unlock();
        }
    }

    static class Log4jModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return log4jlog.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "#";
                case 1:
                    return "Method";
                case 2:
                    return "URL";
                case 3:
                    return "Status";
                case 4:
                    return "Length";
                default:
                    return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Log4jEntry logEntry = log4jlog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.extensionMethod;
                case 2:
                    return logEntry.url;
                case 3:
                    return logEntry.res;
                case 4:
                    return logEntry.length;
                default:
                    return null;
            }
        }
    }

    public static class Log4jEntry {
        final int id;
        final String extensionMethod;
        final String url;
        final String length;
        final String res;

        final IHttpRequestResponse requestResponse;

        public Log4jEntry(int id, String extensionMethod, String url, String res, String length, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.url = url;
            this.length = length;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);

        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            Log4jEntry logEntry = log4jlog.get(rowIndex);
            HRequestTextEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            if (logEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(logEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }
}
