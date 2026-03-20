package burp.utils;

import burp.bean.ConfigBean;
import burp.dao.ConfigDao;

import java.util.HashMap;
import java.util.Map;

/**
 * 国际化工具类
 * 用于管理插件的中英文切换功能
 */
public class I18nUtils {
    // 语言类型枚举
    public enum Language {
        ENGLISH("en"),
        CHINESE("zh");
        
        private final String code;
        
        Language(String code) {
            this.code = code;
        }
        
        public String getCode() {
            return code;
        }
    }
    
    // 当前语言
    private static Language currentLanguage = Language.ENGLISH;
    
    // 语言映射表
    private static final Map<Language, Map<String, String>> languageMap = new HashMap<>();
    
    static {
        // 初始化英文映射
        Map<String, String> enMap = new HashMap<>();
        // AuthUI
        enMap.put("auth.button.clear", "Clear");
        enMap.put("auth.button.save", "Save");
        enMap.put("auth.label.ip", "IP:");
        
        // SqlUI
        enMap.put("sql.checkbox.passive", "Passive Scan");
        enMap.put("sql.checkbox.delete_original", "Delete Original Value");
        enMap.put("sql.checkbox.check_cookie", "Check Cookie");
        enMap.put("sql.checkbox.check_header", "Check Header");
        enMap.put("sql.checkbox.whitelist", "Whitelist Domain");
        enMap.put("sql.checkbox.url_encode", "URL Encode");
        enMap.put("sql.checkbox.boolean_blind", "Boolean Blind");
        enMap.put("sql.button.save_whitelist", "Save Whitelist");
        enMap.put("sql.button.save_header", "Save Headers");
        enMap.put("sql.button.refresh", "Refresh");
        enMap.put("sql.button.clear", "Clear");
        enMap.put("sql.label.whitelist", "Whitelist Domains");
        enMap.put("sql.label.header", "Header Detection List");
        enMap.put("sql.label.payload", "SQL Payload");
        enMap.put("sql.label.error_key", "SQL Error Key");
        enMap.put("sql.button.save_payload", "Save SQL Payload");
        enMap.put("sql.button.save_error_key", "Save SQL Error Key");
        enMap.put("sql.border.scan_options", "Scan Options");
        enMap.put("sql.border.configuration", "Configuration");
        enMap.put("sql.border.actions", "Actions");
        
        // PermUI
        enMap.put("perm.tab.original", "Original Request");
        enMap.put("perm.tab.low", "Low Privilege Request");
        enMap.put("perm.tab.no", "No Privilege Request");
        enMap.put("perm.checkbox.passive", "Passive Scan");
        enMap.put("perm.checkbox.whitelist", "Whitelist Domain");
        enMap.put("perm.button.save_whitelist", "Save Whitelist");
        enMap.put("perm.button.save_auth", "Save Auth Data");
        enMap.put("perm.button.export", "Export Data");
        enMap.put("perm.button.refresh", "Refresh");
        enMap.put("perm.button.clear", "Clear");
        enMap.put("perm.label.whitelist", "Whitelist Domains");
        enMap.put("perm.label.low_auth", "Low Privilege Auth Info");
        enMap.put("perm.label.no_auth", "No Privilege Auth Info (Headers Only)");
        enMap.put("perm.border.scan_options", "Scan Options");
        enMap.put("perm.border.configuration", "Configuration");
        enMap.put("perm.border.actions", "Actions");
        enMap.put("perm.message.no_data", "No data in table");
        enMap.put("perm.message.export_success", "Export successful, copied to clipboard");
        enMap.put("perm.message.fill_whitelist", "Please fill in the whitelist domain first");
        
        // FastjsonUI
        enMap.put("fastjson.button.clear", "Clear");
        enMap.put("fastjson.button.refresh", "Refresh");
        enMap.put("fastjson.checkbox.passive", "Enable Passive Scan");
        enMap.put("fastjson.checkbox.auto_refresh", "Auto Refresh");
        enMap.put("fastjson.message.enter_echo", "Please enter echo command");
        
        // Log4jUI
        enMap.put("log4j.checkbox.passive", "Passive Scan");
        enMap.put("log4j.checkbox.original", "Original Payload");
        enMap.put("log4j.checkbox.params", "Check Parameters");
        enMap.put("log4j.checkbox.headers", "Check Headers");
        enMap.put("log4j.checkbox.whitelist", "Whitelist Domain");
        enMap.put("log4j.checkbox.dns_ip", "DNS");
        enMap.put("log4j.button.save_whitelist", "Save Whitelist");
        enMap.put("log4j.button.save_header", "Save Headers");
        enMap.put("log4j.button.refresh", "Refresh");
        enMap.put("log4j.button.clear", "Clear");
        enMap.put("log4j.label.whitelist", "Whitelist Domains");
        enMap.put("log4j.label.header", "Header Detection List");
        enMap.put("log4j.label.payload", "Payload List");
        enMap.put("log4j.button.save_payload", "Save Payload");
        enMap.put("log4j.border.scan_options", "Scan Options");
        enMap.put("log4j.border.configuration", "Configuration");
        enMap.put("log4j.border.actions", "Actions");
        
        // RouteUI
        enMap.put("route.button.refresh", "Refresh");
        enMap.put("route.button.clear", "Clear");
        enMap.put("route.checkbox.passive", "Passive Scan");
        enMap.put("route.label.tips", "Add Custom Rule: ");
        enMap.put("route.label.name", "Name:");
        enMap.put("route.label.path", "Path:");
        enMap.put("route.label.express", "Express:");
        enMap.put("route.button.add", "Add Rule");
        enMap.put("route.button.delete", "Delete Selected");
        enMap.put("route.button.enable", "Enable/Disable Selected");
        
        // SimilarUI
        enMap.put("similar.label.project", "Current Project: Not Selected");
        enMap.put("similar.button.scan", "Start Scan");
        enMap.put("similar.button.manage", "Project Management");
        enMap.put("similar.button.config", "Configure Main Domain");
        enMap.put("similar.label.domain", " Domain List:");
        enMap.put("similar.label.url", " URL List:");
        enMap.put("similar.label.stats", "Statistics: ");
        enMap.put("similar.label.domain_cache", "Domain Cache");
        enMap.put("similar.label.url_cache", "URL Cache");
        enMap.put("similar.label.main_domain", "Main Domain Configuration:");
        enMap.put("similar.message.select_project", "Please select a project first!");
        enMap.put("similar.table.copy_domain", "Copy Domain");
        enMap.put("similar.table.copy_ip", "Copy IP");
        enMap.put("similar.table.copy_selected", "Copy Selected");
        enMap.put("similar.table.copy_selected_url", "Copy Selected URL");
        enMap.put("similar.table.copy_all_url", "Copy All URLs");
        enMap.put("similar.table.clear_selection", "Clear Selection");
        
        // DomainConfigDialog
        enMap.put("similar.dialog.domain_config_title", "Main Domain Configuration");
        enMap.put("similar.dialog.add_domain", "Add Domain");
        enMap.put("similar.dialog.edit_domain", "Edit Domain");
        enMap.put("similar.dialog.delete_domain", "Delete Domain");
        enMap.put("similar.dialog.save", "Save");
        enMap.put("similar.dialog.domain_list", "Main Domain List:");
        
        // ProjectManageDialog
        enMap.put("similar.dialog.project_manage_title", "Project Management");
        enMap.put("similar.dialog.add_project", "Add Project");
        enMap.put("similar.dialog.delete_project", "Delete Project");
        enMap.put("similar.dialog.select_project", "Select Project");
        
        // FastjsonUI
        enMap.put("fastjson.button.refresh", "Refresh");
        enMap.put("fastjson.checkbox.auto_refresh", "Auto Refresh");
        enMap.put("fastjson.dialog.select_type", "Please select type:");
        enMap.put("fastjson.dialog.tip", "Tip");
        
        // AuthUI
        enMap.put("auth.button.clear", "Clear");
        enMap.put("auth.label.ip", "IP:");
        enMap.put("auth.button.save", "Save");
        
        // SocksUI
        enMap.put("socks.button.save", "Save");
        enMap.put("socks.button.next", "Next");
        enMap.put("socks.checkbox.enable", "Enable Socks");
        enMap.put("socks.border.proxy_pool", "Proxy Pool: (example: 1.2.3.4:7890 or 1.2.3.4:7890:user:pass)");
        enMap.put("socks.border.log", "Log");
        
        // ProjectManageDialog messages
        enMap.put("similar.dialog.input_project_name", "Please enter project name:");
        enMap.put("similar.dialog.create_project_failed", "Create project failed: ");
        enMap.put("similar.dialog.error", "Error");
        enMap.put("similar.dialog.confirm_delete_project", "Are you sure to delete project '");
        enMap.put("similar.dialog.confirm_delete", "Confirm Delete");
        enMap.put("similar.dialog.delete_project_failed", "Delete project failed: ");
        enMap.put("similar.dialog.refresh_project_list_failed", "Refresh project list failed: ");
        
        // DomainConfigDialog messages
        enMap.put("similar.dialog.input_domain", "Please enter domain:");
        enMap.put("similar.dialog.add_domain_title", "Add Domain");
        enMap.put("similar.dialog.domain_exists", "Domain already exists!");
        enMap.put("similar.dialog.tip", "Tip");
        enMap.put("similar.dialog.edit_domain", "Edit domain:");
        enMap.put("similar.dialog.select_domain_to_edit", "Please select a domain to edit!");
        enMap.put("similar.dialog.confirm_delete_domain", "Are you sure to delete the selected domain?");
        enMap.put("similar.dialog.select_domain_to_delete", "Please select a domain to delete!");
        
        // UrlRedirectUI
        enMap.put("redirect.checkbox.passive", "Passive Scan");
        enMap.put("redirect.button.clear", "Clear");
        enMap.put("redirect.border.settings", "Settings");
        enMap.put("redirect.label.parameter", "Parameter");
        enMap.put("redirect.label.parameters", "Parameters");
        enMap.put("redirect.label.payloads", "Payloads");
        enMap.put("redirect.button.add", "Add");
        enMap.put("redirect.button.clear", "Clear");
        enMap.put("redirect.value.yes", "Yes");
        enMap.put("redirect.value.no", "No");
        
        // ConfigUI
        enMap.put("config.label.dnslog", "DNS Log");
        enMap.put("config.label.ip", "IP Address");
        enMap.put("config.label.tool_name", "Tool Name");
        enMap.put("config.label.tool_args", "Tool Arguments");
        enMap.put("config.button.save", "Save Config");
        enMap.put("config.button.refresh", "Refresh");
        enMap.put("config.button.delete", "Delete Selected");
        enMap.put("config.button.clear_cache", "Clear Cache");
        enMap.put("config.button.reset", "Reset Duplicate Check");
        enMap.put("config.message.delete_success", "Delete Successfully");
        enMap.put("config.message.delete_failed", "Delete Failed");
        enMap.put("config.message.save_success", "Save Successfully");
        enMap.put("config.message.reset_success", "Reset Successfully");
        enMap.put("config.title.info", "Info");
        
        // 通用
        enMap.put("common.button.save", "Save");
        enMap.put("common.button.next", "Next");
        enMap.put("common.checkbox.enable", "Enable Socks");
        enMap.put("common.border.proxy_pool", "Proxy Pool: (example: 1.2.3.4:7890 or 1.2.3.4:7890:user:pass)");
        enMap.put("common.border.log", "Log");
        enMap.put("common.label.language", "Language");
        enMap.put("common.message.language_change", "Language changed. Please restart the plugin to apply changes.");
        enMap.put("common.title.info", "Info");
        
        // SocksUI
        enMap.put("socks.message.save_success", "Successfully saved %s records");
        enMap.put("socks.message.invalid_format", "Please enter the correct proxy format");
        enMap.put("socks.message.save_first", "Please save the proxy configuration first");
        enMap.put("socks.message.all_used", "All proxies have been used");
        enMap.put("socks.message.current_proxy", "Currently using IP: %s:%s");
        enMap.put("socks.message.current_proxy_with_user", "Currently using IP: %s:%s Username: %s");
        
        languageMap.put(Language.ENGLISH, enMap);
        
        // 初始化中文映射
        Map<String, String> zhMap = new HashMap<>();
        // AuthUI
        zhMap.put("auth.button.clear", "Clear");
        zhMap.put("auth.button.save", "Save");
        zhMap.put("auth.label.ip", "IP:");
        
        // SqlUI
        zhMap.put("sql.checkbox.passive", "被动扫描");
        zhMap.put("sql.checkbox.delete_original", "删除原始值");
        zhMap.put("sql.checkbox.check_cookie", "检测cookie");
        zhMap.put("sql.checkbox.check_header", "检测header");
        zhMap.put("sql.checkbox.whitelist", "白名单域名检测");
        zhMap.put("sql.checkbox.url_encode", "url编码");
        zhMap.put("sql.checkbox.boolean_blind", "布尔盲注");
        zhMap.put("sql.button.save_whitelist", "保存白名单域名");
        zhMap.put("sql.button.save_header", "保存header");
        zhMap.put("sql.button.refresh", "刷新表格");
        zhMap.put("sql.button.clear", "清空表格");
        zhMap.put("sql.label.whitelist", "白名单域名");
        zhMap.put("sql.label.header", "header检测列表");
        zhMap.put("sql.label.payload", "sql payload");
        zhMap.put("sql.label.error_key", "sql error key");
        zhMap.put("sql.button.save_payload", "保存sql payload");
        zhMap.put("sql.button.save_error_key", "保存sql error key");
        zhMap.put("sql.border.scan_options", "扫描选项");
        zhMap.put("sql.border.configuration", "配置");
        zhMap.put("sql.border.actions", "操作");
        
        // PermUI
        zhMap.put("perm.tab.original", "原始请求包");
        zhMap.put("perm.tab.low", "低权限请求包");
        zhMap.put("perm.tab.no", "无权限请求包");
        zhMap.put("perm.checkbox.passive", "被动扫描");
        zhMap.put("perm.checkbox.whitelist", "白名单域名");
        zhMap.put("perm.button.save_whitelist", "保存白名单");
        zhMap.put("perm.button.save_auth", "保存认证数据");
        zhMap.put("perm.button.export", "导出数据");
        zhMap.put("perm.button.refresh", "刷新表格");
        zhMap.put("perm.button.clear", "清空表格");
        zhMap.put("perm.label.whitelist", "白名单域名");
        zhMap.put("perm.label.low_auth", "低权限认证请求信息");
        zhMap.put("perm.label.no_auth", "无权限认证请求信息(输入请求头信息，不输入请求体信息)");
        zhMap.put("perm.border.scan_options", "扫描选项");
        zhMap.put("perm.border.configuration", "配置");
        zhMap.put("perm.border.actions", "操作");
        zhMap.put("perm.message.no_data", "表格中没有数据");
        zhMap.put("perm.message.export_success", "导出成功，已复制到剪切板");
        zhMap.put("perm.message.fill_whitelist", "请先填写白名单域名");
        
        // FastjsonUI
        zhMap.put("fastjson.button.clear", "Clear");
        zhMap.put("fastjson.button.refresh", "Refresh");
        zhMap.put("fastjson.checkbox.passive", "Enable Passive Scan");
        zhMap.put("fastjson.checkbox.auto_refresh", "Auto Refresh");
        zhMap.put("fastjson.message.enter_echo", "请输入echo命令");
        
        // Log4jUI
        zhMap.put("log4j.checkbox.passive", "被动扫描");
        zhMap.put("log4j.checkbox.original", "原始payload");
        zhMap.put("log4j.checkbox.params", "检测参数");
        zhMap.put("log4j.checkbox.headers", "检测header");
        zhMap.put("log4j.checkbox.whitelist", "白名单域名检测");
        zhMap.put("log4j.checkbox.dns_ip", "dns");
        zhMap.put("log4j.button.save_whitelist", "保存白名单域名");
        zhMap.put("log4j.button.save_header", "保存header");
        zhMap.put("log4j.button.refresh", "刷新表格");
        zhMap.put("log4j.button.clear", "清空表格");
        zhMap.put("log4j.label.whitelist", "白名单域名");
        zhMap.put("log4j.label.header", "header检测列表");
        zhMap.put("log4j.label.payload", "payload 列表");
        zhMap.put("log4j.button.save_payload", "保存payload");
        zhMap.put("log4j.border.scan_options", "扫描选项");
        zhMap.put("log4j.border.configuration", "配置");
        zhMap.put("log4j.border.actions", "操作");
        
        // RouteUI
        zhMap.put("route.button.refresh", "refersh");
        zhMap.put("route.button.clear", "clear");
        zhMap.put("route.checkbox.passive", "passive");
        zhMap.put("route.label.tips", "自定义规则添加: ");
        zhMap.put("route.label.name", "name:");
        zhMap.put("route.label.path", "path:");
        zhMap.put("route.label.express", "express:");
        zhMap.put("route.button.add", "添加规则");
        zhMap.put("route.button.delete", "删除选中规则");
        zhMap.put("route.button.enable", "开启/关闭选中规则");
        
        // SimilarUI
        zhMap.put("similar.label.project", "当前项目: 未选择");
        zhMap.put("similar.button.scan", "开启扫描");
        zhMap.put("similar.button.manage", "项目管理");
        zhMap.put("similar.button.config", "配置主域名");
        zhMap.put("similar.label.domain", " 域名列表:");
        zhMap.put("similar.label.url", " URL列表:");
        zhMap.put("similar.label.stats", "统计信息: ");
        zhMap.put("similar.label.domain_cache", "域名缓存");
        zhMap.put("similar.label.url_cache", "URL缓存");
        zhMap.put("similar.label.main_domain", "主域名配置:");
        zhMap.put("similar.message.select_project", "请先选择项目!");
        zhMap.put("similar.table.copy_domain", "复制域名");
        zhMap.put("similar.table.copy_ip", "复制IP");
        zhMap.put("similar.table.copy_selected", "复制选中内容");
        zhMap.put("similar.table.copy_selected_url", "复制选中URL");
        zhMap.put("similar.table.copy_all_url", "复制全部URL");
        zhMap.put("similar.table.clear_selection", "清除选择");
        
        // DomainConfigDialog
        zhMap.put("similar.dialog.domain_config_title", "主域名配置");
        zhMap.put("similar.dialog.add_domain", "添加域名");
        zhMap.put("similar.dialog.edit_domain", "编辑域名");
        zhMap.put("similar.dialog.delete_domain", "删除域名");
        zhMap.put("similar.dialog.save", "保存");
        zhMap.put("similar.dialog.domain_list", "主域名列表:");
        
        // ProjectManageDialog
        zhMap.put("similar.dialog.project_manage_title", "项目管理");
        zhMap.put("similar.dialog.add_project", "新增项目");
        zhMap.put("similar.dialog.delete_project", "删除项目");
        zhMap.put("similar.dialog.select_project", "选择项目");
        
        // FastjsonUI
        zhMap.put("fastjson.button.refresh", "刷新");
        zhMap.put("fastjson.checkbox.auto_refresh", "自动刷新");
        zhMap.put("fastjson.dialog.select_type", "请选择类型:");
        zhMap.put("fastjson.dialog.tip", "提示");
        
        // AuthUI
        zhMap.put("auth.button.clear", "清空");
        zhMap.put("auth.label.ip", "IP:");
        zhMap.put("auth.button.save", "保存");
        
        // SocksUI
        zhMap.put("socks.button.save", "保存");
        zhMap.put("socks.button.next", "下一个");
        zhMap.put("socks.checkbox.enable", "启用Socks");
        zhMap.put("socks.border.proxy_pool", "代理池: (示例: 1.2.3.4:7890 或 1.2.3.4:7890:user:pass)");
        zhMap.put("socks.border.log", "日志");
        
        // ProjectManageDialog messages
        zhMap.put("similar.dialog.input_project_name", "请输入项目名称:");
        zhMap.put("similar.dialog.create_project_failed", "创建项目失败: ");
        zhMap.put("similar.dialog.error", "错误");
        zhMap.put("similar.dialog.confirm_delete_project", "确定要删除项目 '");
        zhMap.put("similar.dialog.confirm_delete", "确认删除");
        zhMap.put("similar.dialog.delete_project_failed", "删除项目失败: ");
        zhMap.put("similar.dialog.refresh_project_list_failed", "刷新项目列表失败: ");
        
        // DomainConfigDialog messages
        zhMap.put("similar.dialog.input_domain", "请输入域名:");
        zhMap.put("similar.dialog.add_domain_title", "添加域名");
        zhMap.put("similar.dialog.domain_exists", "域名已存在!");
        zhMap.put("similar.dialog.tip", "提示");
        zhMap.put("similar.dialog.edit_domain", "编辑域名:");
        zhMap.put("similar.dialog.select_domain_to_edit", "请先选择要编辑的域名!");
        zhMap.put("similar.dialog.confirm_delete_domain", "确定要删除选中的域名吗?");
        zhMap.put("similar.dialog.select_domain_to_delete", "请先选择要删除的域名!");
        
        // UrlRedirectUI
        zhMap.put("redirect.checkbox.passive", "被动扫描");
        zhMap.put("redirect.button.clear", "清除");
        zhMap.put("redirect.border.settings", "设置");
        zhMap.put("redirect.label.parameter", "参数");
        zhMap.put("redirect.label.parameters", "参数");
        zhMap.put("redirect.label.payloads", "Payloads");
        zhMap.put("redirect.button.add", "添加");
        zhMap.put("redirect.button.clear", "清除");
        zhMap.put("redirect.value.yes", "是");
        zhMap.put("redirect.value.no", "否");
        
        // ConfigUI
        zhMap.put("config.label.dnslog", "DNS日志");
        zhMap.put("config.label.ip", "IP地址");
        zhMap.put("config.label.tool_name", "工具名称");
        zhMap.put("config.label.tool_args", "工具参数");
        zhMap.put("config.button.save", "保存配置");
        zhMap.put("config.button.refresh", "刷新");
        zhMap.put("config.button.delete", "删除选中");
        zhMap.put("config.button.clear_cache", "清除缓存");
        zhMap.put("config.button.reset", "重置重复性校验");
        zhMap.put("config.message.delete_success", "删除成功");
        zhMap.put("config.message.delete_failed", "删除失败");
        zhMap.put("config.message.save_success", "保存成功");
        zhMap.put("config.message.reset_success", "重置成功");
        zhMap.put("config.title.info", "提示");
        
        // 通用
        zhMap.put("common.button.save", "Save");
        zhMap.put("common.button.next", "Next");
        zhMap.put("common.checkbox.enable", "Enable Socks");
        zhMap.put("common.border.proxy_pool", "Proxy Pool: (example: 1.2.3.4:7890 or 1.2.3.4:7890:user:pass)");
        zhMap.put("common.border.log", "Log");
        zhMap.put("common.label.language", "语言");
        zhMap.put("common.message.language_change", "语言已更改，请重启插件以应用更改。");
        zhMap.put("common.title.info", "提示");
        
        // SocksUI
        zhMap.put("socks.message.save_success", "成功保存数据%s条");
        zhMap.put("socks.message.invalid_format", "请输入正确的代理格式");
        zhMap.put("socks.message.save_first", "请先保存代理配置");
        zhMap.put("socks.message.all_used", "所有代理已使用完毕");
        zhMap.put("socks.message.current_proxy", "当前使用ip:%s:%s");
        zhMap.put("socks.message.current_proxy_with_user", "当前使用ip:%s:%s 用户名:%s");
        
        languageMap.put(Language.CHINESE, zhMap);
        
        // 从配置中加载语言设置
        loadLanguageFromConfig();
    }
    
    /**
     * 从配置中加载语言设置
     */
    private static void loadLanguageFromConfig() {
        try {
            ConfigBean config = ConfigDao.getConfig("config", "language");
            if (config != null && "zh".equals(config.getValue())) {
                currentLanguage = Language.CHINESE;
            }
        } catch (Exception e) {
            // 加载失败时使用默认语言
            currentLanguage = Language.ENGLISH;
        }
    }
    
    /**
     * 获取当前语言
     */
    public static Language getCurrentLanguage() {
        return currentLanguage;
    }
    
    /**
     * 设置语言
     */
    public static void setLanguage(Language language) {
        currentLanguage = language;
    }
    
    /**
     * 获取国际化文本
     */
    public static String get(String key) {
        Map<String, String> map = languageMap.get(currentLanguage);
        return map != null ? map.getOrDefault(key, key) : key;
    }
    
    /**
     * 切换语言
     */
    public static void toggleLanguage() {
        currentLanguage = currentLanguage == Language.ENGLISH ? Language.CHINESE : Language.ENGLISH;
    }
    
    /**
     * 检查是否为中文
     */
    public static boolean isChinese() {
        return currentLanguage == Language.CHINESE;
    }
    
    /**
     * 设置是否为中文
     */
    public static void setChinese(boolean isChinese) {
        currentLanguage = isChinese ? Language.CHINESE : Language.ENGLISH;
    }
}