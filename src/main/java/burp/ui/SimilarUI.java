package burp.ui;

import burp.*;
import burp.bean.SimilarDomainResultBean;
import burp.bean.SimilarProjectBean;
import burp.bean.SimilarUrlResultBean;
import burp.dao.SimilarDomainConfigDao;
import burp.dao.SimilarDomainResultDao;
import burp.dao.SimilarProjectDao;
import burp.dao.SimilarUrlResultDao;
import burp.ui.SimilarHelper.*;
import burp.ui.SimilarHelper.bean.Domain;
import burp.ui.SimilarHelper.bean.Project;
import burp.ui.SimilarHelper.bean.URL;
import burp.ui.SimilarHelper.dialog.DomainConfigDialog;
import burp.ui.SimilarHelper.dialog.ProjectManageDialog;
import burp.ui.SimilarHelper.table.DomainTable;
import burp.ui.SimilarHelper.table.URLTable;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.io.IOException;
import java.net.InetAddress;
import java.sql.SQLException;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 相似域名扫描UI主类
 * 负责界面展示和用户交互
 */
public class SimilarUI implements UIHandler, IHttpListener {

    // UI组件
    private JPanel mainPanel;
    private JLabel currentProjectLabel;
    private JToggleButton scanButton;
    private JButton projectManageButton;
    private JButton domainConfigButton;
    private DomainTable domainTable;
    private URLTable urlTable;

    // 核心功能状态
    private boolean scanEnabled = false;
    private boolean isReloading = false;
    private boolean isSelectingProject = false;

    // Burp相关组件
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // 业务数据
    private Project currentProject;
    private List<Project> projects = new ArrayList<>();

    /**
     * 初始化UI和数据
     */
    @Override
    public void init() {
        setupUI();
        setupData();
        loadProjects();
    }

    /**
     * 获取主面板
     */
    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        return mainPanel;
    }

    /**
     * 获取标签页名称
     */
    @Override
    public String getTabName() {
        return "Similar";
    }

    /**
     * 设置UI布局和组件
     */
    private void setupUI() {
        Utils.callbacks.registerHttpListener(this);

        // 创建主面板
        mainPanel = new JPanel(new BorderLayout());

        // 添加控制面板、分割面板和状态面板
        mainPanel.add(createControlPanel(), BorderLayout.NORTH);
        mainPanel.add(createSplitPane(), BorderLayout.CENTER);
        mainPanel.add(createStatsPanel(), BorderLayout.SOUTH);
    }

    /**
     * 创建控制面板
     */
    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        // 初始化控制组件
        currentProjectLabel = new JLabel("当前项目: 未选择");
        scanButton = new JToggleButton("开启扫描");
        projectManageButton = new JButton("项目管理");
        domainConfigButton = new JButton("配置主域名");

        // 添加按钮事件监听
        setupControlButtons();

        // 添加组件到面板
        controlPanel.add(currentProjectLabel);
        controlPanel.add(scanButton);
        controlPanel.add(projectManageButton);
        controlPanel.add(new JLabel("主域名配置:"));
        controlPanel.add(domainConfigButton);

        return controlPanel;
    }

    /**
     * 创建分割面板
     */
    private JSplitPane createSplitPane() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);

        // 域名表格面板
        domainTable = new DomainTable();
        JPanel domainPanel = new JPanel(new BorderLayout());
        domainPanel.add(new JLabel(" 域名列表:"), BorderLayout.NORTH);
        domainPanel.add(new JScrollPane(domainTable), BorderLayout.CENTER);
        splitPane.setLeftComponent(domainPanel);

        // URL表格面板
        urlTable = new URLTable();
        JPanel urlPanel = new JPanel(new BorderLayout());
        urlPanel.add(new JLabel(" URL列表:"), BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);
        splitPane.setRightComponent(urlPanel);

        return splitPane;
    }

    /**
     * 创建状态面板
     */
    private JPanel createStatsPanel() {
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel statsLabel = new JLabel("统计信息: ");
        statsPanel.add(statsLabel);

        // 定时更新统计信息
        Timer statsTimer = new Timer(5000, e -> {
            // 获取缓存统计
            Map<String, Integer> stats = CacheManager.getCacheStats();
            statsLabel.setText(String.format("统计信息: 域名缓存: %d | URL缓存: %d",
                    stats.get("domainIpCache"),
                    stats.get("projectUrlCache")));
        });
        statsTimer.start();

        return statsPanel;
    }

    /**
     * 设置按钮事件监听
     */
    private void setupControlButtons() {
        scanButton.addActionListener(e -> handleScanButtonClick());
        projectManageButton.addActionListener(e -> showProjectManageDialog());
        domainConfigButton.addActionListener(e -> handleDomainConfigButtonClick());
    }

    /**
     * 处理扫描按钮点击事件
     */
    private void handleScanButtonClick() {
        if (currentProject == null && scanButton.isSelected()) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择项目!");
            scanButton.setSelected(false);
        } else {
            scanEnabled = scanButton.isSelected();
            scanButton.setSelected(scanEnabled);
        }
    }

    /**
     * 处理域名配置按钮点击事件
     */
    private void handleDomainConfigButtonClick() {
        if (currentProject == null) {
            JOptionPane.showMessageDialog(mainPanel,
                    "请先选择项目!",
                    "提示",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        DomainConfigDialog dialog = new DomainConfigDialog(
                SwingUtilities.getWindowAncestor(mainPanel),
                currentProject
        );
        dialog.setVisible(true);
    }

    /**
     * 设置扫描状态
     */
    public void setScanEnabled(boolean enabled) {
        this.scanEnabled = enabled;
        if (scanButton != null) {
            scanButton.setSelected(enabled);
        }
    }

    /**
     * 加载项目列表
     */
    private void loadProjects() {
        try {
            List<SimilarProjectBean> projectBeans = SimilarProjectDao.getAllProjects();
            projects.clear();
            for (SimilarProjectBean bean : projectBeans) {
                if (bean != null) {
                    projects.add(new Project(bean));
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("加载项目列表失败: " + e.getMessage());
        }
    }

    /**
     * 显示项目管理对话框
     */
    private void showProjectManageDialog() {
        if (isSelectingProject) {
            return;
        }

        ProjectManageDialog dialog = new ProjectManageDialog(
                SwingUtilities.getWindowAncestor(mainPanel),
                projects,
                this::handleProjectSelection
        );
        dialog.setVisible(true);
    }

    /**
     * 处理HTTP消息
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 跳过不需要处理的情况
        if (messageIsRequest || !scanEnabled || currentProject == null || isReloading) {
            return;
        }

        ThreadManager.execute(() -> {
            try {
                processHttpResponse(messageInfo);
            } catch (Exception e) {
                callbacks.printError("处理HTTP消息失败: " + e.getMessage());
            }
        });
    }

    /**
     * 处理HTTP响应
     */
    private void processHttpResponse(IHttpRequestResponse messageInfo) {
        // 分析请求URL
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        if (shouldFilter(url)) {
            return;
        }

        // 分析响应内容类型
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        String contentType = getResponseContentType(responseInfo);
        if (!isProcessableContentType(contentType)) {
            return;
        }

        // 处理响应内容
        processResponseContent(messageInfo, responseInfo);
    }

    /**
     * 处理响应内容
     */
    private void processResponseContent(IHttpRequestResponse messageInfo, IResponseInfo responseInfo) {
        if (isReloading || currentProject == null) {
            return;
        }

        try {
            byte[] response = messageInfo.getResponse();
            int bodyOffset = responseInfo.getBodyOffset();

            // 处理响应体
            if (response.length - bodyOffset > 1024 * 1024) { // 大于1MB的响应分块处理
                processLargeResponse(response, bodyOffset);
            } else {
                String responseBody = new String(Arrays.copyOfRange(response, bodyOffset, response.length), "UTF-8");
                processExtractedData(responseBody);
            }
        } catch (Exception e) {
            Utils.stderr.println("处理响应内容失败: " + e.getMessage());
        }
    }

    /**
     * 处理大型响应
     */
    private void processLargeResponse(byte[] response, int bodyOffset) throws IOException {
        final int CHUNK_SIZE = 1024 * 1024; // 1MB
        int currentOffset = bodyOffset;

        while (currentOffset < response.length) {
            int endOffset = Math.min(currentOffset + CHUNK_SIZE, response.length);
            String chunk = new String(Arrays.copyOfRange(response, currentOffset, endOffset), "UTF-8");
            processExtractedData(chunk);
            currentOffset = endOffset;
        }
    }

    /**
     * 处理提取的数据
     */
    private void processExtractedData(String content) {
        // 并行提取域名和URL
        CompletableFuture<Set<String>> domainsFuture = CompletableFuture.supplyAsync(() -> extractDomains(content));
        CompletableFuture<Set<String>> urlsFuture = CompletableFuture.supplyAsync(() -> extractUrls(content));

        try {
            // 获取提取结果
            Set<String> domains = domainsFuture.get();
            Set<String> urls = urlsFuture.get();

            // 处理域名
            domains.stream()
                    .filter(this::isDomainRelevant)
                    .forEach(this::processNewDomain);

            // 处理URL
            urls.stream()
                    .filter(this::isUrlRelevant)
                    .forEach(this::processNewUrl);

        } catch (Exception e) {
            Utils.stderr.println("处理提取数据失败: " + e.getMessage());
        }
    }

    /**
     * 处理新发现的域名
     */
    private void processNewDomain(String domain) {
        if (!isDomainMatch(domain) || isReloading) {
            return;
        }

        // 检查缓存
        if (CacheManager.isProjectDomainCached(currentProject.getId(), domain)) {
            return;
        }

        synchronized (this) {
            // 双重检查
            if (CacheManager.isProjectDomainCached(currentProject.getId(), domain)) {
                return;
            }

            // 检查数据库
            if (SimilarDomainResultDao.isDomainExists(currentProject.getId(), domain)) {
                CacheManager.cacheProjectDomain(currentProject.getId(), domain);
                return;
            }
        }

        // 异步解析IP
        CompletableFuture.supplyAsync(() -> getIPWithCache(domain))
                .thenAccept(ip -> {
                    Utils.stdout.println("域名匹配成功: " + domain);
                    updateDomainUI(domain, ip);
                })
                .exceptionally(e -> {
                    Utils.stderr.println("处理域名失败: " + e.getMessage());
                    return null;
                });
    }

    /**
     * 检查域名是否匹配主域名
     * @param domain 需要检查的域名
     * @return 是否匹配
     */
    private boolean isDomainMatch(String domain) {
        if (currentProject == null || currentProject.getMainDomains() == null) {
            return false;
        }

        String lowerDomain = domain.toLowerCase();
        return currentProject.getMainDomains().stream()
                .filter(mainDomain -> mainDomain != null && !mainDomain.isEmpty())
                .map(String::toLowerCase)
                .anyMatch(lowerDomain::endsWith);
    }

    /**
     * 更新域名UI
     */
    private void updateDomainUI(String domain, String ip) {
        if (isReloading) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                // 添加到表格
                Domain entry = new Domain(domain, ip);
                domainTable.addEntry(entry);
                Utils.stdout.println("已添加域名到表格: " + domain);

                // 保存到数据库
                saveDomainToDatabase(entry);
            } catch (Exception e) {
                Utils.stderr.println("添加域名条目失败: " + e.getMessage());
            }
        });
    }

    /**
     * 保存域名到数据库
     */
    private void saveDomainToDatabase(Domain entry) {
        ThreadManager.execute(() -> {
            try {
                SimilarDomainResultBean domainResult = new SimilarDomainResultBean(
                        currentProject.getId(),
                        entry.getDomain(),
                        entry.getIp()
                );

                int newId = SimilarDomainResultDao.saveDomainResult(domainResult);
                if (newId > 0) {
                    entry.setId(newId);
                    SwingUtilities.invokeLater(() -> domainTable.refreshEntry(entry));
                    CacheManager.cacheProjectDomain(currentProject.getId(), entry.getDomain());
                }
            } catch (Exception e) {
                Utils.stderr.println("保存域名到数据库失败: " + e.getMessage());
            }
        });
    }

    /**
     * 处理新发现的URL
     */
    private void processNewUrl(String url) {
        if (isReloading) {
            return;
        }

        synchronized (this) {
            // 检查缓存和数据库
            if (CacheManager.isProjectUrlCached(currentProject.getId(), url)) {
                return;
            }

            if (SimilarUrlResultDao.isUrlExists(currentProject.getId(), url)) {
                CacheManager.cacheProjectUrl(currentProject.getId(), url);
                return;
            }
        }

        // 更新UI和数据库
        SwingUtilities.invokeLater(() -> {
            try {
                // 添加到表格
                URL entry = new URL(url);
                urlTable.addEntry(entry);

                // 保存到数据库
                ThreadManager.execute(() -> saveUrlToDatabase(url));
            } catch (Exception e) {
                Utils.stderr.println("添加URL条目失败: " + e.getMessage());
            }
        });
    }

    /**
     * 保存URL到数据库
     */
    private void saveUrlToDatabase(String url) {
        try {
            SimilarUrlResultBean urlResult = new SimilarUrlResultBean(
                    currentProject.getId(),
                    url
            );
            int newId = SimilarUrlResultDao.saveUrlResult(urlResult);
            if (newId > 0) {
                CacheManager.cacheProjectUrl(currentProject.getId(), url);
            }
        } catch (Exception e) {
            Utils.stderr.println("保存URL到数据库失败: " + e.getMessage());
        }
    }

    /**
     * 项目选择处理
     */
    private void handleProjectSelection(Project project) {
        if (isSelectingProject || project == null) {
            return;
        }

        isSelectingProject = true;
        try {
            ThreadManager.execute(() -> {
                try {
                    switchToNewProject(project);
                } catch (Exception e) {
                    handleProjectSwitchError(e);
                } finally {
                    isSelectingProject = false;
                }
            });
        } catch (Exception e) {
            isSelectingProject = false;
            throw e;
        }
    }

    /**
     * 切换到新项目
     */
    private void switchToNewProject(Project project) throws SQLException {
        // 清理当前项目
        cleanupCurrentProject();

        // 设置新项目
        currentProject = project;
        updateProjectUI(project);

        // 加载项目配置和数据
        List<String> domainConfigs = SimilarDomainConfigDao.getDomainConfigs(project.getId());
        project.setMainDomains(domainConfigs);

        // 检查域名配置
        if (domainConfigs.isEmpty()) {
            showDomainConfigWarning();
        }

        // 加载项目数据
        loadAllProjectData(project.getId());
    }

    /**
     * 加载项目所有数据
     * @param projectId 项目ID
     */
    private void loadAllProjectData(int projectId) throws SQLException {
        // 清空现有数据和缓存
        SwingUtilities.invokeLater(() -> {
            domainTable.clearData();
            urlTable.clearData();
        });
        CacheManager.clearProjectCache(projectId);

        // 并行获取域名和URL数据
        CompletableFuture<List<SimilarDomainResultBean>> domainsFuture = CompletableFuture.supplyAsync(() -> {
            try {
                return SimilarDomainResultDao.getDomainResults(projectId);
            } catch (SQLException e) {
                throw new CompletionException(e);
            }
        });

        CompletableFuture<List<SimilarUrlResultBean>> urlsFuture =
                CompletableFuture.supplyAsync(() -> SimilarUrlResultDao.getUrlResults(projectId));

        // 等待所有数据加载完成
        CompletableFuture.allOf(domainsFuture, urlsFuture).thenRun(() -> {
            try {
                // 处理域名数据
                List<SimilarDomainResultBean> domainResults = domainsFuture.get();
                Map<String, SimilarDomainResultBean> uniqueDomains = new HashMap<>();

                if (domainResults != null) {
                    // 对域名数据去重
                    for (SimilarDomainResultBean result : domainResults) {
                        if (result != null) {
                            String domainKey = result.getDomain().toLowerCase();
                            if (!uniqueDomains.containsKey(domainKey) ||
                                    uniqueDomains.get(domainKey).getId() > result.getId()) {
                                uniqueDomains.put(domainKey, result);
                            }
                        }
                    }
                }

                // 处理URL数据
                List<SimilarUrlResultBean> urlResults = urlsFuture.get();
                Map<String, SimilarUrlResultBean> uniqueUrls = new HashMap<>();

                if (urlResults != null) {
                    // 对URL数据去重
                    for (SimilarUrlResultBean result : urlResults) {
                        if (result != null) {
                            String urlKey = result.getUrl();
                            if (!uniqueUrls.containsKey(urlKey) ||
                                    uniqueUrls.get(urlKey).getId() > result.getId()) {
                                uniqueUrls.put(urlKey, result);
                            }
                        }
                    }
                }

                // 批量更新UI
                SwingUtilities.invokeLater(() -> {
                    // 更新域名表格
                    domainTable.startBatchUpdate();
                    try {
                        for (SimilarDomainResultBean result : uniqueDomains.values()) {
                            domainTable.addEntry(new Domain(result));
                            CacheManager.cacheProjectDomain(projectId, result.getDomain());
                        }
                    } finally {
                        domainTable.endBatchUpdate();
                    }

                    // 更新URL表格
                    urlTable.startBatchUpdate();
                    try {
                        for (SimilarUrlResultBean result : uniqueUrls.values()) {
                            urlTable.addEntry(new URL(result.getUrl()));
                            CacheManager.cacheProjectUrl(projectId, result.getUrl());
                        }
                    } finally {
                        urlTable.endBatchUpdate();
                    }
                });

            } catch (Exception e) {
                Utils.stderr.println("加载项目数据失败: " + e.getMessage());
            }
        }).join();
    }

    /**
     * 更新项目UI
     */
    private void updateProjectUI(Project project) {
        SwingUtilities.invokeLater(() -> {
            currentProjectLabel.setText("当前项目: " + project.getName());
            scanButton.setEnabled(true);
            domainConfigButton.setEnabled(true);
        });
    }

    /**
     * 显示域名配置警告
     */
    private void showDomainConfigWarning() {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                    "该项目还未配置主域名，请先配置主域名！",
                    "提示",
                    JOptionPane.INFORMATION_MESSAGE);
        });
    }

    /**
     * 处理项目切换错误
     */
    private void handleProjectSwitchError(Exception e) {
        Utils.stderr.println("切换项目失败: " + e.getMessage());
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                    "加载项目失败: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE);
        });
    }

    // 信号量用于限制DNS解析并发数
    private final Semaphore dnsResolveSemaphore = new Semaphore(10);

    // 黑名单后缀集合
    private Set<String> blackListSuffixes;

    /**
     * 初始化数据
     */
    private void setupData() {
        // 设置按钮初始状态
        scanButton.setEnabled(false);
        domainConfigButton.setEnabled(false);

        // 初始化黑名单
        initializeBlackList();

        // 设置定时清理任务
        setupCleanupTask();
    }

    /**
     * 初始化黑名单后缀
     */
    private void initializeBlackList() {
        blackListSuffixes = new HashSet<>(Arrays.asList(
                // 图片文件
                ".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".webp", ".svg",
                // 样式和脚本文件
                ".css", ".js", ".jsx", ".ts", ".tsx",
                // 字体文件
                ".woff", ".woff2", ".ttf", ".eot", ".otf",
                // 媒体文件
                ".mp4", ".mp3", ".wav", ".avi", ".mov", ".wmv", ".flv",
                // 文档文件
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                // 压缩文件
                ".zip", ".rar", ".7z", ".tar", ".gz",
                // 其他二进制文件
                ".exe", ".dll", ".so", ".dmg", ".iso",
                // 地图文件
                ".map"
        ));
    }

    /**
     * 设置定时清理任务
     */
    private void setupCleanupTask() {
        Timer cleanupTimer = new Timer(60 * 60 * 1000, e -> { // 每小时执行一次
            ThreadManager.execute(() -> {
                try {
                    // 清理过期的IP缓存
                    CacheManager.cleanExpiredIPCache();

                    // 同步当前项目数据
                    if (currentProject != null) {
                        syncProjectData();
                    }
                } catch (Exception ex) {
                    Utils.stderr.println("执行清理任务失败: " + ex.getMessage());
                }
            });
        });
        cleanupTimer.start();
    }

    /**
     * 同步项目数据
     */
    private void syncProjectData() {
        try {
            List<String> latestConfigs = SimilarDomainConfigDao.getDomainConfigs(currentProject.getId());
            currentProject.setMainDomains(latestConfigs);
        } catch (Exception e) {
            Utils.stderr.println("同步项目数据失败: " + e.getMessage());
        }
    }

    /**
     * 提取域名
     */
    private Set<String> extractDomains(String content) {
        Set<String> domains = new HashSet<>();
        try {
            // 域名匹配正则表达式
            Pattern pattern = Pattern.compile(
                    "(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
            );
            Matcher matcher = pattern.matcher(content);

            // 使用StringBuilder优化字符串操作
            StringBuilder domainBuilder = new StringBuilder();
            while (matcher.find()) {
                domainBuilder.setLength(0);
                domainBuilder.append(matcher.group().toLowerCase());
                String domain = domainBuilder.toString();

                if (!isBlacklistedDomain(domain)) {
                    domains.add(domain);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("提取域名失败: " + e.getMessage());
        }
        return domains;
    }

    /**
     * 提取URL
     */
    private Set<String> extractUrls(String content) {
        Set<String> urls = new HashSet<>();
        try {
            // URL匹配正则表达式
            Pattern pattern = Pattern.compile(
                    "(?i)https?://(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])" +
                            "(?::[0-9]{1,5})?(?:/[^\\s\"'<>\\[\\]{}\\\\^`|]*)?"
            );
            Matcher matcher = pattern.matcher(content);

            while (matcher.find()) {
                String url = matcher.group();
                if (isValidUrl(url)) {
                    urls.add(url);
                }
            }
        } catch (Exception e) {
            callbacks.printError("提取URL失败: " + e.getMessage());
        }
        return urls;
    }

    /**
     * 检查域名是否在黑名单中
     */
    private boolean isBlacklistedDomain(String domain) {
        return blackListSuffixes.stream().anyMatch(domain::endsWith);
    }

    /**
     * 验证URL是否有效
     */
    private boolean isValidUrl(String url) {
        try {
            // 检查URL格式
            new java.net.URL(url);

            // 检查是否包含黑名单后缀
            return !blackListSuffixes.stream()
                    .anyMatch(suffix -> url.toLowerCase().endsWith(suffix));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 检查URL是否需要过滤
     */
    private boolean shouldFilter(String url) {
        return blackListSuffixes.stream()
                .anyMatch(suffix -> url.toLowerCase().endsWith(suffix));
    }

    /**
     * 获取响应内容类型
     */
    private String getResponseContentType(IResponseInfo responseInfo) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.substring("content-type:".length()).trim().toLowerCase();
            }
        }
        return "";
    }

    /**
     * 检查内容类型是否可处理
     */
    private boolean isProcessableContentType(String contentType) {
        return contentType.contains("text/") ||
                contentType.contains("application/json") ||
                contentType.contains("application/xml") ||
                contentType.contains("application/javascript") ||
                contentType.contains("application/x-javascript") ||
                contentType.contains("application/ecmascript") ||
                contentType.contains("application/x-httpd-php");
    }

    /**
     * 获取带缓存的IP地址
     */
    private String getIPWithCache(String domain) {
        // 检查缓存
        String cachedIP = CacheManager.getCachedIP(domain);
        if (cachedIP != null) {
            return cachedIP;
        }

        // 使用信号量限制并发DNS查询
        try {
            return dnsResolveSemaphore.tryAcquire(5, TimeUnit.SECONDS) ?
                    performDNSResolve(domain) : "解析超时";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "解析中断";
        }
    }

    /**
     * 执行DNS解析
     */
    private String performDNSResolve(String domain) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);
            if (addresses.length > 0) {
                StringBuilder ips = new StringBuilder();
                for (InetAddress addr : addresses) {
                    if (ips.length() > 0) {
                        ips.append(", ");
                    }
                    ips.append(addr.getHostAddress());
                }
                String result = ips.toString();
                CacheManager.cacheIP(domain, result);
                return result;
            }
            return "无解析结果";
        } catch (Exception e) {
            return "解析失败: " + e.getMessage();
        } finally {
            dnsResolveSemaphore.release();
        }
    }

    /**
     * 检查域名是否相关
     */
    private boolean isDomainRelevant(String domain) {
        if (currentProject == null || currentProject.getMainDomains() == null) {
            return false;
        }

        String lowerDomain = domain.toLowerCase();
        return currentProject.getMainDomains().stream()
                .filter(Objects::nonNull)
                .map(String::toLowerCase)
                .anyMatch(lowerDomain::endsWith);
    }

    /**
     * 检查URL是否相关
     */
    private boolean isUrlRelevant(String url) {
        try {
            java.net.URL parsedUrl = new java.net.URL(url);
            return isDomainRelevant(parsedUrl.getHost());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 清理当前项目
     */
    private void cleanupCurrentProject() {
        if (currentProject != null) {
            // 停止扫描
            setScanEnabled(false);

            // 清理缓存
            CacheManager.clearProjectCache(currentProject.getId());

            // 清理UI
            SwingUtilities.invokeLater(() -> {
                domainTable.clearData();
                urlTable.clearData();
            });
        }
    }
}