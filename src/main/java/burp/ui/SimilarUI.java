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
import burp.utils.I18nUtils;
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
 * Similar（相似域名/URL 挖掘）模块主类：被动扫描——注册 IHttpListener，扫描开启时
 * 从响应体提取与项目主域名相关的域名/URL，解析 IP、展示表格并持久化。
 *
 * <p>线程模型：UI 在 EDT；processHttpMessage 跑在 Burp 代理监听线程（只做轻量过滤），
 * 实际处理提交 ThreadManager 池；表格写入一律经 invokeLater 切 EDT；
 * 项目切换用 isSelectingProject 标志防并发。</p>
 */
public class SimilarUI implements UIHandler, IHttpListener {

    // UI组件
    private JPanel mainPanel;
    private JLabel currentProjectLabel;
    private static Timer statsTimer; // 持有统计定时器引用，重新初始化时停止旧的，避免叠加泄漏
    private static Timer cleanupTimer;
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
    private volatile Project currentProject;
    private List<Project> projects = new ArrayList<>();

    /**
     * 初始化UI和数据
     */
    @Override
    public void init() {
        ThreadManager.start();
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
        currentProjectLabel = new JLabel(I18nUtils.get("similar.label.project"));
        scanButton = new JToggleButton(I18nUtils.get("similar.button.scan"));
        projectManageButton = new JButton(I18nUtils.get("similar.button.manage"));
        domainConfigButton = new JButton(I18nUtils.get("similar.button.config"));

        // 添加按钮事件监听
        setupControlButtons();

        // 添加组件到面板
        controlPanel.add(currentProjectLabel);
        controlPanel.add(scanButton);
        controlPanel.add(projectManageButton);
        controlPanel.add(new JLabel(I18nUtils.get("similar.label.main_domain")));
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
        domainPanel.add(new JLabel(I18nUtils.get("similar.label.domain")), BorderLayout.NORTH);
        domainPanel.add(new JScrollPane(domainTable), BorderLayout.CENTER);
        splitPane.setLeftComponent(domainPanel);

        // URL表格面板
        urlTable = new URLTable();
        JPanel urlPanel = new JPanel(new BorderLayout());
        urlPanel.add(new JLabel(I18nUtils.get("similar.label.url")), BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);
        splitPane.setRightComponent(urlPanel);

        return splitPane;
    }

    /**
     * 创建状态面板
     */
    private JPanel createStatsPanel() {
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel statsLabel = new JLabel(I18nUtils.get("similar.label.stats"));
        statsPanel.add(statsLabel);

        // 定时更新统计信息（重新初始化时先停止旧定时器，避免同一进程内多实例叠加）
        if (statsTimer != null) statsTimer.stop();
        statsTimer = new Timer(5000, e -> {
            // 获取缓存统计
            Map<String, Integer> stats = CacheManager.getCacheStats();
            statsLabel.setText(String.format(I18nUtils.get("similar.label.stats") + " %s | %s",
                    I18nUtils.get("similar.label.domain_cache") + ": " + stats.get("domainIpCache"),
                    I18nUtils.get("similar.label.url_cache") + ": " + stats.get("projectUrlCache")));
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
    /** 切换扫描开关（EDT）：未选项目就开启时弹窗提示并复位。 */
    private void handleScanButtonClick() {
        if (currentProject == null && scanButton.isSelected()) {
            JOptionPane.showMessageDialog(mainPanel, I18nUtils.get("similar.message.select_project"));
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
                    I18nUtils.get("similar.message.select_project"),
                    I18nUtils.get("config.title.info"),
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
     * HTTP 监听回调（Burp 代理监听线程）：仅做轻量过滤，实际处理提交 ThreadManager 池。
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
        if (messageInfo.getResponse() == null) {
            return;
        }
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
        // 并行提取域名和URL（走 ThreadManager 有界池，禁止 commonPool 无界堆积）。
        // 用 thenCombine 组合结果而不是 future.get()：父任务若在同一池的线程上阻塞等待
        // 子任务，高流量下可能占满池线程导致"父等子、子等池"的饥饿死锁。
        ThreadManager.supplyAsync(() -> extractDomains(content))
                .thenCombine(ThreadManager.supplyAsync(() -> extractUrls(content)),
                        SimilarUI::mergeExtractionResults)
                .thenAccept(this::processExtractionResults)
                .exceptionally(e -> {
                    Utils.stderr.println("处理提取数据失败: " + e.getMessage());
                    return null;
                });
    }

    /** 合并两个提取结果（纯函数，任一为 null 时以空集合兜底）。 */
    private static ExtractionPair mergeExtractionResults(Set<String> domains, Set<String> urls) {
        return new ExtractionPair(
                domains == null ? new LinkedHashSet<>() : domains,
                urls == null ? new LinkedHashSet<>() : urls);
    }

    /** 按相关性过滤后分发域名/URL 处理（ThreadManager 池线程）。 */
    private void processExtractionResults(ExtractionPair results) {
        // 处理域名
        results.domains.stream()
                .filter(this::isDomainRelevant)
                .forEach(this::processNewDomain);

        // 处理URL
        results.urls.stream()
                .filter(this::isUrlRelevant)
                .forEach(this::processNewUrl);
    }

    /** 域名/URL 提取结果对。 */
    private static final class ExtractionPair {
        private final Set<String> domains;
        private final Set<String> urls;

        private ExtractionPair(Set<String> domains, Set<String> urls) {
            this.domains = domains;
            this.urls = urls;
        }
    }

    /**
     * 处理新发现的域名：缓存/数据库双重检查（synchronized(this)）→ 异步解析 IP → 更新 UI 并入库。
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

        // 异步解析IP：解析失败返回 null，不再把"解析失败: xxx"之类的错误字符串写入 ip 字段
        ThreadManager.supplyAsync(() -> getIPWithCache(domain))
                .thenAccept(ip -> {
                    if (ip == null) {
                        return;
                    }
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
     * 更新域名 UI 并入库（切 EDT 加表格行，再经 ThreadManager 池写库并回写真实 ID）。
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

                // 保存到数据库
                saveDomainToDatabase(entry);
            } catch (Exception e) {
                Utils.stderr.println("添加域名条目失败: " + e.getMessage());
            }
        });
    }

    /**
     * 域名结果入库（ThreadManager 池线程）：upsert 成功后回写真实 ID、刷新表格行并缓存。
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
     * 处理新发现的 URL：缓存/数据库双重检查后，切 EDT 加表格行并异步入库。
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
     * 项目选择回调（EDT，来自 ProjectManageDialog）：提交切换处理到池；
     * isSelectingProject 标志在任务被拒时同样复位，防止切换功能永久锁死。
     */
    private void handleProjectSelection(Project project) {
        if (isSelectingProject || project == null) {
            return;
        }

        isSelectingProject = true;
        // 任务被有界池拒绝时必须复位标志，否则项目切换功能永久锁死
        boolean accepted = false;
        try {
            accepted = ThreadManager.execute(() -> {
                try {
                    switchToNewProject(project);
                } catch (Exception e) {
                    handleProjectSwitchError(e);
                } finally {
                    isSelectingProject = false;
                }
            });
        } finally {
            if (!accepted) {
                isSelectingProject = false;
            }
        }
    }

    /**
     * 切换到新项目（ThreadManager 池线程）：清理旧项目 → 设置新项目 → 加载域名配置 → 批量载入历史数据。
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
     * 批量载入项目历史域名/URL 结果（并行查库 + 按 key 去重保留最小 id + 批量刷表），
     * 并以 join 阻塞至加载完成。
     * 注意：此处两个 DB 查询用 CompletableFuture.supplyAsync 直接提交到 ForkJoinPool.commonPool
     * （IO 等待，当前并发量下可接受；与 processExtractedData 的"禁 commonPool"约定不同，见其注释）。
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
     * 更新项目显示标签并启用控制按钮（切 EDT）。
     */
    private void updateProjectUI(Project project) {
        SwingUtilities.invokeLater(() -> {
            currentProjectLabel.setText(I18nUtils.get("similar.label.current_project") + " " + project.getName());
            scanButton.setEnabled(true);
            domainConfigButton.setEnabled(true);
        });
    }

    /**
     * 项目无主域名配置时弹窗提醒（切 EDT）。
     */
    private void showDomainConfigWarning() {
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                    I18nUtils.get("similar.message.no_domain"),
                    I18nUtils.get("config.title.info"),
                    JOptionPane.INFORMATION_MESSAGE);
        });
    }

    /**
     * 项目切换失败处理：记录日志并弹窗（切 EDT）。
     */
    private void handleProjectSwitchError(Exception e) {
        Utils.stderr.println("切换项目失败: " + e.getMessage());
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(mainPanel,
                    I18nUtils.get("similar.message.load_failed") + " " + e.getMessage(),
                    I18nUtils.get("config.title.info"),
                    JOptionPane.ERROR_MESSAGE);
        });
    }

    // 信号量用于限制DNS解析并发数（10）
    private final Semaphore dnsResolveSemaphore = new Semaphore(10);

    // 静态资源后缀黑名单：命中的域名/URL 不提取，对应请求不处理
    private Set<String> blackListSuffixes;

    /**
     * 初始化数据：按钮初始禁用、初始化黑名单、注册定时清理任务。
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
     * 初始化静态资源后缀黑名单（图片/脚本/字体/媒体/文档/压缩等）。
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


    /** 停止两个 Swing 定时器（插件卸载时调用；static 防止多实例重复持有）。 */
    public static void shutdown() {
        if (statsTimer != null) {
            statsTimer.stop();
            statsTimer = null;
        }
        if (cleanupTimer != null) {
            cleanupTimer.stop();
            cleanupTimer = null;
        }
    }

    /**
     * 注册每小时执行的清理任务：清过期 IP 缓存 + 同步当前项目域名配置。
     * Timer 回调在 EDT，处理提交 ThreadManager 池。
     */
    private void setupCleanupTask() {
        if (cleanupTimer != null) cleanupTimer.stop();
        cleanupTimer = new Timer(60 * 60 * 1000, e -> { // 每小时执行一次
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
     * 从库重新同步当前项目的主域名配置（ThreadManager 池线程）。
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
     * 正则提取响应体中的域名（ThreadManager 池线程，过滤黑名单后缀，小写归一）。
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
     * 正则提取响应体中的 http(s) URL（ThreadManager 池线程，经 isValidUrl 校验）。
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
     * 获取带缓存的IP地址。解析失败/超时/中断返回 null（调用方据此跳过入库，避免错误字符串污染 ip 字段）。
     */
    private String getIPWithCache(String domain) {
        // 检查缓存
        String cachedIP = CacheManager.getCachedIP(domain);
        if (cachedIP != null) {
            return cachedIP;
        }

        // 负缓存：近期解析失败的域名短期内直接跳过，
        // 避免不可解析域名在后续每个响应中重复触发 DNS 查询（缓存穿透）
        if (CacheManager.isIpCacheNegative(domain)) {
            return null;
        }

        // 使用信号量限制并发DNS查询
        try {
            return dnsResolveSemaphore.tryAcquire(5, TimeUnit.SECONDS) ?
                    performDNSResolve(domain) : null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * 执行 DNS 解析（全程持有 DNS 信号量，finally 释放）：
     * 全部 IP 逗号拼接，成功写正缓存、失败/无结果写负缓存，返回 null 表示解析失败。
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
            Utils.stderr.println("DNS 无解析结果: " + domain);
            CacheManager.cacheIpFailure(domain);
            return null;
        } catch (Exception e) {
            Utils.stderr.println("DNS 解析失败 " + domain + ": " + e.getMessage());
            CacheManager.cacheIpFailure(domain);
            return null;
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
     * 项目切换前的清理：停扫描、清项目缓存、清表格（切 EDT）。
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
