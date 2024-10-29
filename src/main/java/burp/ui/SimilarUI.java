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
import burp.utils.Utils;

import java.sql.SQLException;
import java.util.*;
import javax.swing.*;
import javax.swing.Timer;
import java.awt.*;
import java.util.List;

public class SimilarUI implements UIHandler, IHttpListener {
    private JPanel mainPanel; // 主面板
    private JLabel currentProjectLabel;
    private JToggleButton scanButton;
    private JButton projectManageButton;
    private JButton domainConfigButton;
    private OptimizedDomainTable domainTable;
    private OptimizedURLTable urlTable;

    // 数据存储
    private Project currentProject;
    private List<Project> projects = new ArrayList<>();
    private Set<String> blackListSuffixes;
    /**
     * 检测核心方法
     *
     * @param messageInfo
     */
    public static void Check(IHttpRequestResponse messageInfo) {

    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 检查是否开启扫描且有选择项目
        if (!scanButton.isSelected() || currentProject == null || messageIsRequest) {
            return;
        }

        ThreadManager.execute(() -> {
            try {
                IRequestInfo requestInfo = Utils.helpers.analyzeRequest(messageInfo);
                String url = requestInfo.getUrl().toString();

                // 检查是否需要过滤
                if (shouldFilter(url)) {
                    return;
                }

                String domain = requestInfo.getUrl().getHost();
                processNewDomain(domain);
                processNewUrl(url);

            } catch (Exception e) {
                Utils.stderr.println("处理HTTP消息失败: " + e.getMessage());
                e.printStackTrace(Utils.stderr);
            }
        });
    }

    // 添加更新域名表格的方法
    private void updateDomainTable(int projectId) {
        try {
            List<SimilarDomainResultBean> domainResults = SimilarDomainResultDao.getDomainResults(projectId);

            if (domainResults != null && !domainResults.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        domainTable.clearData();
                        for (SimilarDomainResultBean result : domainResults) {
                            if (result != null) {
                                domainTable.addEntry(new DomainEntry(result));
                            }
                        }
                    } catch (Exception e) {
                        Utils.stderr.println("更新域名表格失败: " + e.getMessage());
                    }
                });
            }
        } catch (SQLException e) {
            Utils.stderr.println("获取域名数据失败: " + e.getMessage());
        }
    }

    @Override
    public void init() {
        // 初始化UI
        setupUI();
        // 初始化数据
        setupData();
        // 加载项目列表
        loadProjects();
        // 初始化黑名单
        initializeBlackList();
    }

    private void processNewDomain(String domain) {
        // 检查域名是否匹配
        if (!isDomainMatch(domain)) {
            return;
        }

        // 检查缓存
        if (CacheManager.isProjectDomainCached(currentProject.getId(), domain)) {
            return;
        }

        Utils.stdout.println("域名匹配成功: " + domain);

        // 获取IP（使用缓存）
        String ip = getIPWithCache(domain);

        // 更新UI
        SwingUtilities.invokeLater(() -> {
            try {
                DomainEntry entry = new DomainEntry(domain, ip);
                domainTable.addEntry(entry);
                Utils.stdout.println("已添加域名到表格: " + domain);

                // 异步保存到数据库
                ThreadManager.execute(() -> {
                    try {
                        final SimilarDomainResultBean domainResult = new SimilarDomainResultBean(
                                currentProject.getId(), domain, ip);
                        int newId = SimilarDomainResultDao.saveDomainResult(domainResult);
                        if (newId > 0) {
                            entry.setId(newId);
                            SwingUtilities.invokeLater(() -> domainTable.refreshEntry(entry));
                            // 添加到缓存
                            CacheManager.cacheProjectDomain(currentProject.getId(), domain);
                        }
                    } catch (Exception e) {
                        Utils.stderr.println("保存域名到数据库失败: " + e.getMessage());
                    }
                });

            } catch (Exception e) {
                Utils.stderr.println("添加域名条目失败: " + e.getMessage());
            }
        });
    }

    private void processNewUrl(String url) {
        // 检查缓存
        if (CacheManager.isProjectUrlCached(currentProject.getId(), url)) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                urlTable.addEntry(new URLEntry(url));

                // 异步保存到数据库
                ThreadManager.execute(() -> {
                    try {
                        SimilarUrlResultBean urlResult = new SimilarUrlResultBean(
                                currentProject.getId(), url);
                        int newId = SimilarUrlResultDao.saveUrlResult(urlResult);
                        if (newId > 0) {
                            CacheManager.cacheProjectUrl(currentProject.getId(), url);
                        }
                    } catch (Exception e) {
                        Utils.stderr.println("保存URL到数据库失败: " + e.getMessage());
                    }
                });

            } catch (Exception e) {
                Utils.stderr.println("添加URL条目失败: " + e.getMessage());
            }
        });
    }

    private String getIPWithCache(String domain) {
        String cachedIP = CacheManager.getCachedIP(domain);
        if (cachedIP != null) {
            return cachedIP;
        }

        String ip = resolveIP(domain);
        if (!"解析失败".equals(ip)) {
            CacheManager.cacheIP(domain, ip);
        }
        return ip;
    }

    private void loadProjects() {
        // 获取 SimilarProjectBean 列表并转换为 Project 列表
        List<SimilarProjectBean> projectBeans = SimilarProjectDao.getAllProjects();
        projects.clear(); // 清空现有列表
        for (SimilarProjectBean bean : projectBeans) {
            projects.add(new Project(bean));
        }
    }
    private void loadProjectData(int projectId) throws SQLException {
        // 清空表格和缓存
        domainTable.clearData();
        urlTable.clearData();
        CacheManager.clearProjectCache(projectId);

        // 批量加载数据
        domainTable.startBatchUpdate();
        try {
            List<SimilarDomainResultBean> domainResults = SimilarDomainResultDao.getDomainResults(projectId);
            if (domainResults != null) {
                for (SimilarDomainResultBean result : domainResults) {
                    if (result != null) {
                        domainTable.addEntry(new DomainEntry(result));
                        CacheManager.cacheProjectDomain(projectId, result.getDomain());
                    }
                }
            }
        } finally {
            domainTable.endBatchUpdate();
        }

        // 批量加载URL数据
        urlTable.startBatchUpdate();
        try {
            List<SimilarUrlResultBean> urlResults = SimilarUrlResultDao.getUrlResults(projectId);
            if (urlResults != null) {
                for (SimilarUrlResultBean result : urlResults) {
                    if (result != null) {
                        urlTable.addEntry(new URLEntry(result.getUrl()));
                        CacheManager.cacheProjectUrl(projectId, result.getUrl());
                    }
                }
            }
        } finally {
            urlTable.endBatchUpdate();
        }
    }
    private boolean shouldFilter(String url) {
        return blackListSuffixes.stream()
                .anyMatch(suffix -> url.toLowerCase().endsWith(suffix));
    }

    private boolean isDomainMatch(String domain) {
        if (currentProject == null || currentProject.getMainDomains() == null) {
            return false;
        }

        String lowerDomain = domain.toLowerCase();
        for (String mainDomain : currentProject.getMainDomains()) {
            if (mainDomain != null && !mainDomain.isEmpty() &&
                    lowerDomain.endsWith(mainDomain.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    private void initializeBlackList() {
        blackListSuffixes = new HashSet<>(Arrays.asList(
                ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3"
        ));
    }
    private String resolveIP(String domain) {
        try {
            return java.net.InetAddress.getByName(domain).getHostAddress();
        } catch (Exception e) {
            return "解析失败";
        }
    }
    private void showProjectManageDialog() {
        ProjectManageDialog dialog = new ProjectManageDialog(
                SwingUtilities.getWindowAncestor(mainPanel),
                projects,
                this::onProjectSelected
        );
        dialog.setVisible(true);
    }
    private void onProjectSelected(Project project) {
        ThreadManager.execute(() -> {
            try {
                currentProject = project;
                SwingUtilities.invokeLater(() ->
                        currentProjectLabel.setText("当前项目: " + project.getName())
                );

                // 加载域名配置
                List<String> domainConfigs = SimilarDomainConfigDao.getDomainConfigs(project.getId());
                project.setMainDomains(domainConfigs);

                // 加载历史数据
                loadProjectData(project.getId());

            } catch (SQLException e) {
                Utils.stderr.println("加载项目数据失败: " + e.getMessage());
            }
        });
    }
    // 初始化数据
    private void setupData() {
        // 项目管理按钮点击事件
        projectManageButton.addActionListener(e -> showProjectManageDialog());

        // 扫描按钮状态改变事件
        scanButton.addActionListener(e -> {
            if (currentProject == null && scanButton.isSelected()) {
                JOptionPane.showMessageDialog(mainPanel, "请先选择项目!");
                scanButton.setSelected(false);
                return;
            }
        });

        // 域名配置变更事件
        domainConfigButton.addActionListener(e -> {
            if (currentProject != null) {
                DomainConfigDialog dialog = new DomainConfigDialog(
                        SwingUtilities.getWindowAncestor(mainPanel),
                        currentProject
                );
                dialog.setVisible(true);
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                        "请先选择项目!",
                        "提示",
                        JOptionPane.WARNING_MESSAGE);
            }
        });
    }

    // 初始化ui
    private void setupUI() {
        // 注册消息监听
        Utils.callbacks.registerHttpListener(this);

        // 创建主面板
        mainPanel = new JPanel(new BorderLayout());

        // 顶部控制面板
        JPanel controlPanel = createControlPanel();

        // 分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5); // 平均分配空间

        // 左侧域名表格
        domainTable = new OptimizedDomainTable();
        JPanel domainPanel = new JPanel(new BorderLayout());
        domainPanel.add(new JLabel(" 域名列表:"), BorderLayout.NORTH);
        domainPanel.add(new JScrollPane(domainTable), BorderLayout.CENTER);
        splitPane.setLeftComponent(domainPanel);

        // 右侧URL表格
        urlTable = new OptimizedURLTable();
        JPanel urlPanel = new JPanel(new BorderLayout());
        urlPanel.add(new JLabel(" URL列表:"), BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);
        splitPane.setRightComponent(urlPanel);

        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // 添加统计面板
        JPanel statsPanel = createStatsPanel();
        mainPanel.add(statsPanel, BorderLayout.SOUTH);
    }

    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        currentProjectLabel = new JLabel("当前项目: 未选择");
        scanButton = new JToggleButton("开启扫描");
        projectManageButton = new JButton("项目管理");
        domainConfigButton = new JButton("配置主域名");

        controlPanel.add(currentProjectLabel);
        controlPanel.add(scanButton);
        controlPanel.add(projectManageButton);
        controlPanel.add(new JLabel("主域名配置:"));
        controlPanel.add(domainConfigButton);

        return controlPanel;
    }

    private JPanel createStatsPanel() {
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel statsLabel = new JLabel("统计信息: ");
        statsPanel.add(statsLabel);

        // 定期更新统计信息
        Timer statsTimer = new Timer(5000, e -> {
            Map<String, Integer> stats = CacheManager.getCacheStats();
            statsLabel.setText(String.format("统计信息: 域名缓存: %d | URL缓存: %d",
                    stats.get("domainIpCache"),
                    stats.get("projectUrlCache")));
        });
        statsTimer.start();

        return statsPanel;
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return mainPanel;
    }

    @Override
    public String getTabName() {
        return "Similar";
    }


}
