package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ui.UIHelper.GridBagConstraintsHelper;
import burp.utils.I18nUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/** SOCKS 代理设置面板：维护代理池（socks.json 的 pool 字段持久化，账号密码明文）、
 *  "下一个代理"轮换（移除已用项后原地取用）与 Burp 项目级 socks_proxy 开关
 *  （经 callbacks.loadConfigFromJson 提交完整配置）。 */
public class SocksUI implements UIHandler {
    private JPanel panel;
    private JButton saveButton;
    private JButton nextButton;
    private JCheckBox enableCheckBox;
    private Boolean dns_over_socks;
    private String host;
    private int port;
    private Boolean use_proxy;
    private Boolean use_user_options;
    private String username;
    private String password;
    private JTextPane ipTextField;
    private JTextPane logTextField;
    private List<ProxyConfig> proxyConfigs;
    private int currentIndex = -1;

    /** 代理池条目；username/password 清洗换行符，明文持久化到 socks.json。 */
    private static class ProxyConfig {
        String ip;
        String port;
        String username;
        String password;

        public ProxyConfig(String ip, String port, String username, String password) {
            this.ip = ip;
            this.port = port;
            this.username = username != null ? username.trim().replaceAll("[\r\n]", "") : "";
            this.password = password != null ? password.trim().replaceAll("[\r\n]", "") : "";
        }
    }

    @Override
    public void init() {
        setupUI();
        setupData();
        setupListeners();
    }

    /**
     * 挂载按钮监听器（从 getPanel 迁出，避免 getter 产生副作用与重复挂载）。
     */
    private void setupListeners() {
        // 保存配置：解析代理池（复用 Utils.parseProxyPool：端口数字校验 + 转义清洗），
        // 同时持久化到 socks.json 的 pool 字段，插件重载后无需重新录入
        saveButton.addActionListener(new AbstractAction() {
            public void actionPerformed(ActionEvent evt) {
                proxyConfigs = new ArrayList<>();
                for (String[] parts : Utils.parseProxyPool(ipTextField.getText())) {
                    proxyConfigs.add(new ProxyConfig(parts[0], parts[1], parts[2], parts[3]));
                }

                if (!proxyConfigs.isEmpty()) {
                    currentIndex = -1;
                    saveProxyPool(proxyConfigs);
                    JOptionPane.showMessageDialog(null, String.format(I18nUtils.get("socks.message.save_success"), proxyConfigs.size()), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(null, I18nUtils.get("socks.message.invalid_format"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        // 切换代理：移除上一个已用代理后，原地取下一个（旧实现的 +1 取模会跳过队首元素）
        nextButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (proxyConfigs == null || proxyConfigs.isEmpty()) {
                    JOptionPane.showMessageDialog(null, I18nUtils.get("socks.message.save_first"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                if (currentIndex >= 0 && currentIndex < proxyConfigs.size()) {
                    proxyConfigs.remove(currentIndex);
                }

                if (proxyConfigs.isEmpty()) {
                    JOptionPane.showMessageDialog(null, I18nUtils.get("socks.message.all_used"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                if (currentIndex < 0 || currentIndex >= proxyConfigs.size()) {
                    currentIndex = 0;
                }
                // remove 之后目标下标的元素已顺移为"下一个未用代理"，原地取用即可；
                // 旧实现的 +1 取模会跳过相邻元素导致轮换顺序错乱
                ProxyConfig currentConfig = proxyConfigs.get(currentIndex);

                String message;
                if (!currentConfig.username.isEmpty()) {
                    message = String.format(I18nUtils.get("socks.message.current_proxy_with_user"), currentConfig.ip, currentConfig.port, currentConfig.username);
                } else {
                    message = String.format(I18nUtils.get("socks.message.current_proxy"), currentConfig.ip, currentConfig.port);
                }

                JOptionPane.showMessageDialog(null, message, I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                writeIpPortSettings(Utils.callbacks, currentConfig, enableCheckBox.isSelected());
            }
        });

        // 启用/禁用代理
        enableCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean enabled = enableCheckBox.isSelected();
                isEnableSettings(Utils.callbacks, enabled);
                String currentText = logTextField.getText();
                String newText = currentText + (enabled ? "Socks Enable\n" : "Socks Disable\n");
                logTextField.setText(newText);
            }
        });
    }

    private void setupData() {
        if (!isConfigFileExist()){
            saveSettings(Utils.callbacks);
        } else {
            loadProxyPool();
        }
    }

    /** 持久化代理池到 socks.json 的 pool 字段，插件重载后无需重新录入。
     *  注意：username/password 以明文存入（与既有行为一致，后续如需加密需同步处理 loadProxyPool 的读取逻辑）。 */
    private void saveProxyPool(List<ProxyConfig> configs) {
        try {
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"), "utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            if (jsonObject == null) {
                jsonObject = new JSONObject();
            }
            com.alibaba.fastjson.JSONArray pool = new com.alibaba.fastjson.JSONArray();
            for (ProxyConfig config : configs) {
                JSONObject entry = new JSONObject();
                entry.put("ip", config.ip);
                entry.put("port", config.port);
                entry.put("username", config.username);
                entry.put("password", config.password);
                pool.add(entry);
            }
            jsonObject.put("pool", pool);
            Utils.writeString(jsonObject.toJSONString(), Utils.SocksConfigFile("socks.json"), "utf-8");
        } catch (Exception e) {
            Utils.stderr.println("Socks pool save failed: " + e.getMessage());
        }
    }

    /** 启动时从 socks.json 恢复代理池列表与输入框内容。 */
    private void loadProxyPool() {
        try {
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"), "utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            if (jsonObject == null) {
                return;
            }
            com.alibaba.fastjson.JSONArray pool = jsonObject.getJSONArray("pool");
            if (pool == null || pool.isEmpty()) {
                return;
            }
            StringBuilder text = new StringBuilder();
            proxyConfigs = new ArrayList<>();
            for (int i = 0; i < pool.size(); i++) {
                JSONObject entry = pool.getJSONObject(i);
                if (entry == null) continue;
                String ipAddr = entry.getString("ip");
                String port = entry.getString("port");
                if (ipAddr == null || port == null) continue;
                String user = entry.getString("username");
                String pass = entry.getString("password");
                ProxyConfig config = new ProxyConfig(ipAddr, port, user, pass);
                proxyConfigs.add(config);
                if (text.length() > 0) text.append('\n');
                text.append(config.ip).append(':').append(config.port);
                if (!config.username.isEmpty()) {
                    text.append(':').append(config.username).append(':').append(config.password);
                }
            }
            ipTextField.setText(text.toString());
            currentIndex = -1;
        } catch (Exception e) {
            Utils.stderr.println("Socks pool load failed: " + e.getMessage());
        }
    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        saveButton = new JButton(I18nUtils.get("socks.button.save"));
        panel.add(saveButton,new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        nextButton = new JButton(I18nUtils.get("socks.button.next"));
        panel.add(nextButton,new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        enableCheckBox =  new JCheckBox(I18nUtils.get("socks.checkbox.enable"));
        panel.add(enableCheckBox,new GridBagConstraintsHelper(3, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        JSplitPane jSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        ipTextField = new JTextPane();
        ipTextField.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("socks.border.proxy_pool")));
        ipTextField.setEditable(true);
        logTextField = new JTextPane();
        logTextField.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("socks.border.log")));
        logTextField.setEditable(false);
        jSplitPane.setDividerLocation(0.5);
        jSplitPane.setResizeWeight(0.5);

        jSplitPane.setLeftComponent(ipTextField);
        jSplitPane.setRightComponent(logTextField);
        panel.add(jSplitPane,new GridBagConstraintsHelper(0, 1, 0, 0).setInsets(5).setIpad(0, 0).setWeight(1.0d, 1.0d).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
    }

    /** 将指定代理写入 Burp 项目 socks_proxy 配置（loadConfigFromJson 一次性提交）并同步回写 socks.json。 */
    public void writeIpPortSettings(IBurpExtenderCallbacks callbacks, ProxyConfig config, boolean enable) {
        try{
            int port;
            try {
                port = Integer.parseInt(config.port.trim());
            } catch (NumberFormatException nfe) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("socks.message.invalid_port"), I18nUtils.get("config.title.info"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            // 先读取现有配置
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"),"utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            // 配置项缺失时 getBoolean 返回 null，自动拆箱会 NPE；用 TRUE.equals 做空安全读取
            boolean dns_over_socks_update = Boolean.TRUE.equals(jsonObject.getBoolean("dns_over_socks"));
            boolean use_user_options_update = Boolean.TRUE.equals(jsonObject.getBoolean("use_user_options"));

            // 组装完整 socks_proxy 配置并一次性提交：旧实现按字段拆成 7 段字符串拼接，
            // 值含引号即产生非法 JSON，且中途失败会留下半更新状态
            JSONObject socksProxy = new JSONObject();
            socksProxy.put("dns_over_socks", dns_over_socks_update);
            socksProxy.put("use_user_options", use_user_options_update);
            socksProxy.put("use_proxy", enable);
            socksProxy.put("host", config.ip);
            socksProxy.put("port", port);
            socksProxy.put("username", config.username);
            socksProxy.put("password", config.password);
            JSONObject root = new JSONObject();
            JSONObject connections = new JSONObject();
            connections.put("socks_proxy", socksProxy);
            JSONObject projectOptions = new JSONObject();
            projectOptions.put("connections", connections);
            root.put("project_options", projectOptions);
            callbacks.loadConfigFromJson(root.toJSONString());

            // 将新配置写回文件：直接修改"已读出的完整对象"再整体写回，
            // 避免用新建对象覆盖整文件导致 saveProxyPool 持久化的 pool 字段丢失
            jsonObject.put("use_proxy", enable);
            jsonObject.put("use_user_options", use_user_options_update);
            jsonObject.put("dns_over_socks", dns_over_socks_update);
            jsonObject.put("host", config.ip);
            jsonObject.put("port", port);
            jsonObject.put("username", config.username);
            jsonObject.put("password", config.password);
            Utils.writeString(jsonObject.toJSONString(), Utils.SocksConfigFile("socks.json"), "utf-8");

            // 更新日志
            String currentText = logTextField.getText();
            String newText = currentText + "Socks Setting Success\n" +
                    "Current ip: " + config.ip +
                    " port: " + config.port;
            if (!config.username.isEmpty()) {
                newText += " username: " + config.username;
            }
            newText += "\n";
            logTextField.setText(newText);

        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    /** 启用/禁用代理：更新 socks.json 的 use_proxy 后按当前 host/port 重发配置。 */
    public void isEnableSettings(IBurpExtenderCallbacks callbacks, boolean enable) {
        try{
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"),"utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);

            // 更新启用状态
            jsonObject.put("use_proxy", enable);

            // 将更新后的配置写回文件
            Utils.writeString(jsonObject.toJSONString(), Utils.SocksConfigFile("socks.json"), "utf-8");

            // host/port 缺失时 getInteger 返回 null，拆箱 NPE；显式判空并记录原因
            String hostValue = jsonObject.getString("host");
            Integer portValue = jsonObject.getInteger("port");
            if (hostValue == null || portValue == null) {
                Utils.stderr.println("Socks settings incomplete: missing host or port in socks.json");
                return;
            }
            ProxyConfig config = new ProxyConfig(
                    hostValue,
                    String.valueOf(portValue),
                    jsonObject.getString("username"),
                    jsonObject.getString("password")
            );

            writeIpPortSettings(callbacks, config, enable);
        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    /** 首次初始化时写入默认 socks.json（127.0.0.1:7890，代理关闭）。 */
    public void saveSettings(IBurpExtenderCallbacks callbacks) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("use_proxy", false);
        jsonObject.put("use_user_options", false);
        jsonObject.put("dns_over_socks", false);
        jsonObject.put("host", "127.0.0.1");
        jsonObject.put("port", 7890);  // 注意这里改成了数字类型
        jsonObject.put("username", "");
        jsonObject.put("password", "");
        String sockinfo = jsonObject.toJSONString();
        try{
            Utils.writeString(sockinfo, Utils.SocksConfigFile("socks.json"), "utf-8");
        }catch (Exception e){
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 判断 socks.json 配置文件是否已存在。 */
    public boolean isConfigFileExist() {
        File file = new File(Utils.WORKDIR + "socks.json");
        return file.exists();
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "SOCKS Settings";
    }
}