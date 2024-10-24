package burp.ui;

import burp.*;
import burp.bean.SimilarSimilarSubDomainBean;
import burp.bean.SimilarSubDomainBean;
import burp.bean.SimilarUrlBean;
import burp.dao.*;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;
import cn.hutool.core.date.DateTime;
import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimilarUI implements UIHandler, IHttpListener {
    public static final String DOMAIN_NAME_PATTERN = "((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";
    public static final String USELESS_EXTENSIONS = "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|bz2|" +
            "cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|mjs|mp2|mp3" +
            "|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar" +
            "|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd" +
            "|zip|zip";
    public static final String USELESS_URL_EXTENSIONS = "js|css|" + USELESS_EXTENSIONS;
    private static final List<GrepSubDomainEntry> grepSubDomainlog = new ArrayList<>(); //
    private static final List<GrepSubdomainUrlEntry> grepSubDomainUrllog = new ArrayList<>(); //
    private static final List<SimilarSubDomainEntry> similarDomainlog = new ArrayList<>(); //
    private static final List<String> parameterList = new ArrayList<>(); // 参数列表
    private static final List<String> urlHashList = new ArrayList<>(); // url hash list
    private static final int DATA_MAX_SIZE = 5 * 1024 * 1024;
    private static final Set<String> ALLOWED_CONTENT_TYPES = new HashSet<>(Arrays.asList(
            "application/javascript", "text/", "application/json", "application/xml"
    ));
    private static final String URL_PATTERN = "[\"'`]([a-zA-Z0-9/=_{}\\?&!:\\.-]+/[a-zA-Z0-9/=_{}\\?&!:\\.-]+(\\.jspx|\\.jsp|\\.html|\\.php|\\.do|\\.aspx|\\.action|\\.json)*)[\"'`]";
    private static JTable GrepSubDomainTable;
    private static JTable GrepSubUrlTable;
    private static JTable SimilarSubDomainTable;
    private static List<String> rootDomain = new ArrayList<>();
    private static Set<String> uniqueDomain = new HashSet<>();
    private static Set<String> uniqueUrl = new HashSet<>();
    private static Set<String> uniqueSimilarDomain = new HashSet<>();
    private JPanel panel; // 主面板
    private JLabel projectnameJLabel; // 项目名称
    private JButton openOrCloseJButton; // 开启或关闭
    private JButton projectManageJButton; //
    private JButton projectRootDomainManage; //
    private static String projectName;
    private static boolean isOpen;

    /**
     * 检测核心方法
     *
     * @param messageInfo
     */
    public static void Check(IHttpRequestResponse messageInfo) {
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(messageInfo);
        String method = analyzeRequest.getMethod();
        String host = messageInfo.getHttpService().getHost();
        URL rdurlURL = analyzeRequest.getUrl();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();
        Set<String> domains = new HashSet<>();
        Set<String> urls = new HashSet<>();
        // 如果method不是get或者post方式直接返回
        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }
        // 如果域名不在白名单,直接返回
        if (!Utils.isMatchDomainName(host, rootDomain)) {
            return;
        }

        if (!UrlCacheUtil.checkUrlUnique("similar", method, rdurlURL, paraLists)) {
            return;
        }

        if (uselessExtension(url, USELESS_EXTENSIONS)) {
            return;
        }


        byte[] response = messageInfo.getResponse();

        if (response != null) {
            List<String> respHeaders = Utils.helpers.analyzeResponse(messageInfo.getResponse()).getHeaders();
            if (checkContentType(respHeaders)) {
                // 如果相应包长度大于DATA_MAX_SIZE,则截取
                if (response.length >= DATA_MAX_SIZE) {
                    response = subByte(response, 0, DATA_MAX_SIZE);
                }
                String decodeRespText = decodeResp(new String(response));
                Set<String> respDomains = grepSubDomain(decodeRespText);
                Set<String> respUrls = grepUrls(decodeRespText);
                domains.addAll(respDomains);
                urls.addAll(respUrls);
            }
        }


        for (String domain : domains) {
            if (isSubdomain(domain)) {
                // 如果uniqueDomain里没有 ,则添加
                if (!uniqueDomain.contains(domain)) {
                    uniqueDomain.add(domain);
                    String domainIp = getDomainIp(domain);
                    addSubDomain(domain, domainIp);
                }
            } else if (isSimilarSubDomain(domain)) {
                // 如果domain=rootDomain,直接返回
                if (Utils.isMatchDomainName(domain, rootDomain)) {
                    break;
                }
                if (!uniqueSimilarDomain.contains(domain)) {
                    uniqueSimilarDomain.add(domain);
                    String domainIp = getDomainIp(domain);
                    addSimilarDomain(domain, domainIp);
                }
            }
        }
        for (String url1 : urls) {
            if (!uniqueUrl.contains(url1)) {
                uniqueUrl.add(url1);
                addSubdomainUrl(url1);
            }
        }
    }

    /**
     * 判断是否为相似域名
     *
     * @param domain
     * @return
     */
    private static boolean isSimilarSubDomain(String domain) {
        for (String s : rootDomain) {
            //思路：考虑将rootdomain进行切割，例如baidu.com使用切割成baidu com，然后对baidu进行相似度匹配
            String[] tmp = s.split("\\.");
            //通过切割的长度取需要匹配的部分，通过这个来避免当用户设置根域名为www.baidu.com的时候，会匹配成www,baidu的问题，目前直接取baidu,com
            String similarRegex = String.format("((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)*(?!-)[A-Za-z0-9-]{0,63}%s[A-Za-z0-9-]{0,63}(?<!-)\\.%s",
                    tmp[tmp.length - 2], tmp[tmp.length - 1]);
            Pattern similarPattern = Pattern.compile(similarRegex);
            Matcher matcher = similarPattern.matcher(domain);
            return matcher.find();
        }
        return false;
    }

    /**
     * 提取传入子域名字符串的根域名
     *
     * @param subDomain
     * @return
     */
    public static String getRootDomain(String subDomain) {
        if (subDomain == null || subDomain.isEmpty()) {
            return null;
        }

        String[] parts = subDomain.split("\\.");
        int length = parts.length;

        // 根域名至少包含两个部分（例如 example.com）
        if (length < 2) {
            return null;
        }

        // 检查是否是顶级域名的特殊情况（如 co.uk, com.au 等）
        if (isSpecialTLD(parts[length - 2] + "." + parts[length - 1])) {
            if (length >= 3) {
                return parts[length - 3] + "." + parts[length - 2] + "." + parts[length - 1];
            } else {
                return null;
            }
        }

        return parts[length - 2] + "." + parts[length - 1];
    }

    /**
     * 判断是否是特殊顶级域名
     *
     * @param tld
     * @return
     */
    private static boolean isSpecialTLD(String tld) {
        String[] specialTLDs = {
                "com.cn"
                // 可以根据需要添加更多特殊顶级域名
        };

        for (String specialTLD : specialTLDs) {
            if (tld.equalsIgnoreCase(specialTLD)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 判断是否为子域名
     *
     * @param domain
     * @return
     */
    private static boolean isSubdomain(String domain) {
        for (String s : rootDomain) {
            if (domain.endsWith("." + s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查是否为指定后缀
     *
     * @param urlPath
     * @param extensions
     * @return
     */
    private static boolean uselessExtension(String urlPath, String extensions) {
        String[] extList = extensions.split("\\|");
        for (String item : extList) {
            if (urlPath.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

    private static boolean checkUrlInDomainList(String url) {
        String[] urlParts = url.split("/");
        String hostPart = urlParts[2];

        String[] hostParts = hostPart.split("\\.");
        String domain = hostParts[hostParts.length - 2] + "." + hostParts[hostParts.length - 1];  // 获取二级域名部分

        for (String domainInList : rootDomain) {
            if (domain.equalsIgnoreCase(domainInList)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 匹配响应包中的域名
     *
     * @param httpResponse
     * @return
     */
    private static Set<String> grepSubDomain(String httpResponse) {
        Set<String> domains = new HashSet<>();
        Pattern pDomainNameOnly = Pattern.compile(DOMAIN_NAME_PATTERN);
        Matcher matcher = pDomainNameOnly.matcher(httpResponse);
        while (matcher.find()) {
            String domain = matcher.group().toLowerCase();
            // 替换掉因正则缺陷匹配到以URL、Unicode编码开头的域名，例如2fwww.baidu.com, 252fwww.baidu.com, 002fwww.baidu.com
            if (domain.startsWith("2f")) {
                domain = domain.replaceFirst("2f", "");
            }
            if (domain.startsWith("252f")) {
                domain = domain.replaceFirst("252f", "");
            }
            if (domain.startsWith("3a")) {
                domain = domain.replaceFirst("3a", "");
            }
            if (domain.startsWith("253a")) {
                domain = domain.replaceFirst("253a", "");
            }
            if (domain.startsWith("u002f")) {
                domain = domain.replaceFirst("u002f", "");
            }
            domains.add(domain);
        }
        return domains;
    }

    /**
     * 匹配响应包中的url
     *
     * @param httpResponse
     * @return
     */
    private static Set<String> grepUrls(String httpResponse) {
        Set<String> urls = new HashSet<>();
        Pattern pDomainNameOnly = Pattern.compile(URL_PATTERN,Pattern.DOTALL);
        Matcher matcher = pDomainNameOnly.matcher(httpResponse);
        while (matcher.find()) {
            String group = matcher.group(1);
            if (group.length()<=4 ||checkApiEndSwith(group)){
                continue;
            }
            if (checkUrlInDomainList(group)){
                urls.add(matcher.group(1));
            }
        }
        return urls;
    }

    /**
     *判断是否以非接口后缀结尾
     * @param group
     * @return
     */
    private static boolean checkApiEndSwith(String group) {
        //定义非法路径后缀
        String[] c= {".jpg",".png",".js",".css",".jpeg",".gif"};
        for(String w:c) {
            if(group.endsWith(w)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 对返回包进行解码
     *
     * @param resp
     * @return
     */
    private static String decodeResp(String resp) {
        if (urlCode(resp)) {
            while (true) {
                try {
                    int oldlen = resp.length();
                    resp = URLDecoder.decode(resp);
                    int currentlen = resp.length();
                    if (oldlen > currentlen) {
                        continue;
                    } else {
                        break;
                    }
                } catch (Exception e) {
                    break;
                }
            }
        }
        if (unicodeCode(resp)) {
            //unicode解码
            while (true) {
                try {
                    int oldlen = resp.length();
                    resp = StringEscapeUtils.unescapeJava(resp);
                    int currentlen = resp.length();
                    if (oldlen > currentlen) {
                        continue;
                    } else {
                        break;
                    }
                } catch (Exception e) {
                    break;
                }
            }
        }
        return resp;
    }

    /**
     * 检测是否有url
     *
     * @param line
     * @return
     */
    private static boolean urlCode(String line) {
        String patternRule = "(%(\\p{XDigit}{2}))";
        Pattern pattern = Pattern.compile(patternRule);
        Matcher matcher = pattern.matcher(line.toLowerCase());
        return matcher.find();
    }

    /**
     * 检测是否有unicode
     *
     * @param line
     * @return
     */
    private static boolean unicodeCode(String line) {
        String patternRule = "(\\\\u(\\p{XDigit}{4}))";
        Pattern pattern = Pattern.compile(patternRule);
        Matcher matcher = pattern.matcher(line.toLowerCase());
        return matcher.find();
    }

    /**
     * 截取过长的js
     *
     * @param b
     * @param srcPos
     * @param length
     * @return
     */
    private static byte[] subByte(byte[] b, int srcPos, int length) {
        byte[] b1 = new byte[length];
        System.arraycopy(b, srcPos, b1, 0, length);
        return b1;
    }

    /**
     * 检测返回包ContentType
     *
     * @param headers
     * @return
     */
    private static boolean checkContentType(List<String> headers) {
        String contentType = headers.stream()
                .filter(header -> header.toLowerCase().startsWith("content-type: "))
                .findFirst()
                .map(header -> header.substring(13).trim())
                .orElse("");

        if (contentType.isEmpty()) {
            return false;
        }

        return ALLOWED_CONTENT_TYPES.stream().anyMatch(contentType::contains);
    }



    /**
     * 添加url
     *
     * @param url
     */
    private static void addSubdomainUrl(String url) {
        SimilarUrlDao.addUrlByProjectName(projectName, url, DateTime.now().toString());
        synchronized (grepSubDomainUrllog) {
            int id = grepSubDomainUrllog.size();
            grepSubDomainUrllog.add(new GrepSubdomainUrlEntry(id, url, DateTime.now().toString()));
            GrepSubUrlTable.updateUI();
        }
    }

    /**
     * 添加子域名
     *
     * @param domain
     * @param ip
     */
    private static void addSubDomain(String domain, String ip) {
        SimilarSubDomainDao.addByRootDomain(getRootDomain(domain), domain, ip, DateTime.now().toString());
        synchronized (grepSubDomainlog) {
            int id = grepSubDomainlog.size();
            grepSubDomainlog.add(new GrepSubDomainEntry(id, domain, ip, DateTime.now().toString()));
            GrepSubDomainTable.updateUI();
        }
    }

    /**
     * 相似域名添加
     *
     * @param domain
     * @param ip
     */
    private static void addSimilarDomain(String domain, String ip) {
        SimilarSimilarSubDomainDao.addSimilarByRootDomain(projectName, domain, ip, DateTime.now().toString());
        synchronized (similarDomainlog) {
            int id = similarDomainlog.size();
            similarDomainlog.add(new SimilarSubDomainEntry(id, domain, ip, DateTime.now().toString()));
            SimilarSubDomainTable.updateUI();
        }
    }

    /**
     * 获取域名对应的IP
     *
     * @param domain
     * @return
     */
    private static String getDomainIp(String domain) {
        try {
            return InetAddress.getByName(domain).getHostAddress();
        } catch (UnknownHostException ne) {
            return "Unknown";
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (isOpen){
            if ((toolFlag == 64 || toolFlag == 32 || toolFlag == 4) && !messageIsRequest) {
                if (!projectName.isEmpty() && rootDomain.size() > 0) {
                    Check(messageInfo);
                }
            }
        }
    }

    @Override
    public void init() {
        setupUI();
        setupData();

    }

    // 初始化数据
    private void setupData() {
        openOrCloseJButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 当按钮被确认
                if (openOrCloseJButton.getText().equals("Open")) {
                    isOpen = false;
                    openOrCloseJButton.setText("Close");
                    openOrCloseJButton.setForeground(Color.RED);
                } else {
                    isOpen = true;
                    openOrCloseJButton.setText("Open");
                    openOrCloseJButton.setForeground(Color.GREEN);
                }
            }
        });


        projectManageJButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ProjectManage nP = new ProjectManage(ProjectManage.PROJECTMODE, "");
                int project = JOptionPane.showConfirmDialog(null, nP, "", JOptionPane.OK_CANCEL_OPTION);
                if (project == 0) {
                    // 当选择或切换项目的时候 需要初始化一些数据
                    projectName = nP.itemList.getSelectedValue();
                    projectnameJLabel.setText("Project Name: " + projectName);
                    projectnameJLabel.setForeground(Color.GREEN);
                    grepSubDomainlog.clear();
                    grepSubDomainUrllog.clear();
                    similarDomainlog.clear();
                    GrepSubDomainTable.updateUI();
                    SimilarSubDomainTable.updateUI();
                    uniqueDomain.clear();
                    uniqueUrl.clear();
                    uniqueSimilarDomain.clear();
                    // 清空并执行重新获取域名
                    rootDomain.clear();
                    new ProjectManage(ProjectManage.DOMAINMODE, projectName);
                    for (String s : rootDomain) {
                        List<SimilarSubDomainBean> rootDomains = SimilarSubDomainDao.getByRootDomain(s);
                        List<SimilarSimilarSubDomainBean> similarDomains = SimilarSimilarSubDomainDao.getSimilarBypProjectName(projectName);
                        List<SimilarUrlBean> urls = SimilarUrlDao.getUrlByProjectName(projectName);

                        for (SimilarSubDomainBean subDomainBean : rootDomains) {
                            synchronized (grepSubDomainlog) {
                                int id = grepSubDomainlog.size();
                                grepSubDomainlog.add(new GrepSubDomainEntry(id, subDomainBean.getSubDomainName(), subDomainBean.getIpAddress(), subDomainBean.getCreateTime()));
                            }
                        }
                        for (SimilarSimilarSubDomainBean subDomainBean : similarDomains) {
                            synchronized (similarDomainlog) {
                                int id = similarDomainlog.size();
                                similarDomainlog.add(new SimilarSubDomainEntry(id, subDomainBean.getSubDomainName(), subDomainBean.getIpAddress(), subDomainBean.getCreateTime()));
                            }
                        }
                        for (SimilarUrlBean subDomainBean : urls) {
                            synchronized (grepSubDomainUrllog) {
                                int id = grepSubDomainUrllog.size();
                                grepSubDomainUrllog.add(new GrepSubdomainUrlEntry(id, subDomainBean.getUrl(), subDomainBean.getCreateTime()));
                            }
                        }
                    }

                    GrepSubDomainTable.updateUI();
                    GrepSubUrlTable.updateUI();
                    SimilarSubDomainTable.updateUI();
                }
            }
        });
        projectRootDomainManage.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ProjectManage nP = new ProjectManage(ProjectManage.DOMAINMODE, projectName);
                int project = JOptionPane.showConfirmDialog(null, nP, "", JOptionPane.OK_CANCEL_OPTION);
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
        // 添加一个projectname显示字段
        projectnameJLabel = new JLabel("Project Name: ");
        topPanel.add(projectnameJLabel);
        // 添加分隔符
        topPanel.add(new JSeparator(JSeparator.HORIZONTAL));
        // 添加开启关闭按钮
        openOrCloseJButton = new JButton("Open or Close");
        topPanel.add(openOrCloseJButton);
        // 添加项目管理按钮
        projectManageJButton = new JButton("Project Manage");
        topPanel.add(projectManageJButton);
        // 添加项目主域名管理按钮
        projectRootDomainManage = new JButton("Project RootDomain Manage");
        topPanel.add(projectRootDomainManage);

        // 添加JTabbedPane到BorderLayout.CENTER
        JTabbedPane tabbedPane = new JTabbedPane();


        // 添加左右分割面板
        JSplitPane leftRightSplitPaneGrep = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, topPanel, panel);
        // 设置leftRightSplitPane对称分割
        leftRightSplitPaneGrep.setResizeWeight(0.5);
        // 设置分割线
        leftRightSplitPaneGrep.setDividerSize(1);

        // leftRightSplitPaneGrep左边添加GrepRootDomainTable
        GrepSubDomainTable = new GrepSubDomainTable(new GrepSubDomainModel());
        JScrollPane GrepRootDomainTableScrollPane = new JScrollPane(GrepSubDomainTable);
        leftRightSplitPaneGrep.setLeftComponent(GrepRootDomainTableScrollPane);

        // leftRightSplitPaneGrep右边添加GrepRootUrlTable
        GrepSubUrlTable = new GrepSubdomainUrlTable(new GrepSubdomainUrlModel());
        JScrollPane GrepRootUrlTableScrollPane = new JScrollPane(GrepSubUrlTable);
        leftRightSplitPaneGrep.setRightComponent(GrepRootUrlTableScrollPane);

        // 添加左右分割面板
        JSplitPane leftRightSplitPaneSimilar = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, topPanel, panel);
        // 设置leftRightSplitPane对称分割
        leftRightSplitPaneSimilar.setResizeWeight(0.5);
        // 设置分割线
        leftRightSplitPaneSimilar.setDividerSize(1);

        // leftRightSplitPaneSimilar左边添加SimilarRootDomainTable
        SimilarSubDomainTable = new SimilarSubDomainTable(new SimilarSubDomainModel());
        JScrollPane SimilarRootDomainTableScrollPane = new JScrollPane(SimilarSubDomainTable);
        leftRightSplitPaneSimilar.setLeftComponent(SimilarRootDomainTableScrollPane);

        //  leftRightSplitPaneSimilar右边添加SimilarRootUrlTable
        JPanel jPanel = new JPanel();
        leftRightSplitPaneSimilar.setRightComponent(jPanel);

        tabbedPane.add("Grep", leftRightSplitPaneGrep);
        tabbedPane.add("Similar", leftRightSplitPaneSimilar);


        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(tabbedPane, BorderLayout.CENTER);
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "Similar";
    }


    // 项目管理 弹出Components
    private static class ProjectManage extends JPanel {
        private static final int PROJECTMODE = 0;
        private static final int DOMAINMODE = 1;
        public DefaultListModel<String> list = new DefaultListModel<String>();
        private int mode;
        private String projectName;
        private JLabel label1;
        private JScrollPane scrollPane1;
        private JList<String> itemList;
        private JTextField inputTextFiled;
        private JButton add;
        private JButton remove;


        public ProjectManage(int mode, String projectName) {
            this.mode = mode;
            this.projectName = projectName;
            initComponents();
        }

        /**
         * 加载数据
         */
        private void loadData() {
            HashSet<String> data;
            switch (mode) {
                case PROJECTMODE:
                    data = SimilarProjectDao.getAllProject();
                    break;
                case DOMAINMODE:
                    data = SimilarRootDomainDao.getRootDomainNameByProjectName(projectName);
                    break;
                default:
                    data = new HashSet<>();
                    break;
            }
            for (String s : data) {
                list.addElement(s);
            }
            if (mode == DOMAINMODE) {
                rootDomain.clear();
                for (String s : data) {
                    rootDomain.add(s);
                }
            }
        }

        private void initComponents() {
            label1 = new JLabel();
            scrollPane1 = new JScrollPane();
            itemList = new JList<>(list);
            inputTextFiled = new JTextField();
            remove = new JButton("Remove");
            add = new JButton("Add");
            setLayout(new GridBagLayout());
            // 第一行：label1 居中
            add(label1, new GridBagConstraintsHelper(0, 0, 2, 1)
                    .setAnchor(GridBagConstraints.CENTER)
                    .setFill(GridBagConstraints.NONE)
                    .setWeight(0.0, 0.0)
                    .setInsets(5));

            // 第二行：scrollPane1 填满剩余空间并包含 JList
            add(scrollPane1, new GridBagConstraintsHelper(0, 1, 2, 1)
                    .setAnchor(GridBagConstraints.CENTER)
                    .setFill(GridBagConstraints.BOTH)
                    .setWeight(1.0, 1.0)
                    .setInsets(5));
            scrollPane1.setViewportView(itemList);
            itemList.setVisibleRowCount(10); // 设置 JList 可见的行数
            scrollPane1.setPreferredSize(new Dimension(200, itemList.getPreferredScrollableViewportSize().height));


            // 第三行：inputTextField 填满水平空间
            add(inputTextFiled, new GridBagConstraintsHelper(0, 2, 2, 1)
                    .setAnchor(GridBagConstraints.CENTER)
                    .setFill(GridBagConstraints.HORIZONTAL)
                    .setWeight(1.0, 0.0)
                    .setInsets(5));

            // 第四行：remove 和 add 按钮并排显示
            add(remove, new GridBagConstraintsHelper(0, 3)
                    .setAnchor(GridBagConstraints.CENTER)
                    .setFill(GridBagConstraints.HORIZONTAL)
                    .setWeight(0.5, 0.0)
                    .setInsets(5));

            add(add, new GridBagConstraintsHelper(1, 3)
                    .setAnchor(GridBagConstraints.CENTER)
                    .setFill(GridBagConstraints.HORIZONTAL)
                    .setWeight(0.5, 0.0)
                    .setInsets(5));

            label1.setText(mode == PROJECTMODE ? "Project Name" : "RootDomain Name");
            loadData();

            remove.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String item = itemList.getSelectedValue();
                    switch (mode) {
                        case PROJECTMODE:
                            SimilarProjectDao.deleteByProjectName(item);
                            break;
                        case DOMAINMODE:
                            SimilarRootDomainDao.deleteByProjectName(projectName, item);
                            break;
                        default:
                            break;
                    }
                    list.removeElement(item);
                }
            });

            add.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String name = inputTextFiled.getText();
                    if (name.isEmpty()) {
                        return;
                    }
                    switch (mode) {
                        case PROJECTMODE:
                            SimilarProjectDao.addProjectByProjectName(name);
                            break;
                        case DOMAINMODE:
                            SimilarRootDomainDao.addRootDomain(projectName, name);
                            break;
                        default:
                            break;
                    }
                    list.addElement(name);
                    inputTextFiled.setText("");
                }
            });
        }

    }

    // 子域名的实体类
    private static class GrepSubDomainEntry {
        private int id;
        private String domain;
        private String ip;
        private String time;

        public GrepSubDomainEntry(int id, String domain, String ip, String time) {
            this.id = id;
            this.domain = domain;
            this.ip = ip;
            this.time = time;
        }
    }

    // 子域名表格
    private static class GrepSubDomainTable extends JTable {
        public GrepSubDomainTable(TableModel dm) {
            super(dm);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            super.changeSelection(row, col, toggle, extend);
        }
    }

    // 子域名模型
    private static class GrepSubDomainModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return grepSubDomainlog.size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            GrepSubDomainEntry grepSubDomainEntry = grepSubDomainlog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return grepSubDomainEntry.id;
                case 1:
                    return grepSubDomainEntry.domain;
                case 2:
                    return grepSubDomainEntry.ip;
                case 3:
                    return grepSubDomainEntry.time;
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
                    return "domain";
                case 2:
                    return "ip";
                case 3:
                    return "time";
                default:
                    return null;
            }
        }
    }

    // url实体类
    private static class GrepSubdomainUrlEntry {
        private int id;
        private String url;
        private String time;

        public GrepSubdomainUrlEntry(int id, String url, String time) {
            this.id = id;
            this.url = url;
            this.time = time;
        }
    }

    // url表格
    private static class GrepSubdomainUrlTable extends JTable {
        public GrepSubdomainUrlTable(TableModel dm) {
            super(dm);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }
    }

    // url模型
    private static class GrepSubdomainUrlModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return grepSubDomainUrllog.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            GrepSubdomainUrlEntry grepRootUrlEntry = grepSubDomainUrllog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return grepRootUrlEntry.id;
                case 1:
                    return grepRootUrlEntry.url;
                case 2:
                    return grepRootUrlEntry.time;
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
                    return "url";
                case 2:
                    return "time";
                default:
                    return null;
            }
        }
    }

    // 相似域名实体类
    private static class SimilarSubDomainEntry {
        private int id;
        private String domain;
        private String ip;
        private String time;

        public SimilarSubDomainEntry(int id, String domain, String ip, String time) {
            this.id = id;
            this.domain = domain;
            this.ip = ip;
            this.time = time;
        }
    }

    // 相似域名表格
    private static class SimilarSubDomainTable extends JTable {
        public SimilarSubDomainTable(TableModel dm) {
            super(dm);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }
    }

    // 相似域名模型
    private static class SimilarSubDomainModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return similarDomainlog.size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            SimilarSubDomainEntry similarRootDomainEntry = similarDomainlog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return similarRootDomainEntry.id;
                case 1:
                    return similarRootDomainEntry.domain;
                case 2:
                    return similarRootDomainEntry.ip;
                case 3:
                    return similarRootDomainEntry.time;
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
                    return "domain";
                case 2:
                    return "ip";
                case 3:
                    return "time";
                default:
                    return null;
            }
        }
    }


}
