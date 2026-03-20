package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ui.UIHepler.GridBagConstraintsHelper;
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

/**
 * @Author Xm17
 * @Date 2024-06-13 22:02
 */
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

    // 新增代理配置类
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
    }

    private void setupData() {
        if (!isConfigFileExist()){
            saveSettings(Utils.callbacks);
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

    // 修改写入代理设置方法
    public void writeIpPortSettings(IBurpExtenderCallbacks callbacks, ProxyConfig config, boolean enable) {
        try{
            // 先读取现有配置
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"),"utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            boolean dns_over_socks_update = jsonObject.getBoolean("dns_over_socks");
            boolean use_user_options_update = jsonObject.getBoolean("use_user_options");

            // 创建新的配置对象
            JSONObject newConfig = new JSONObject();
            newConfig.put("use_proxy", enable);
            newConfig.put("use_user_options", use_user_options_update);
            newConfig.put("dns_over_socks", dns_over_socks_update);
            newConfig.put("host", config.ip);
            newConfig.put("port", Integer.parseInt(config.port.trim()));
            newConfig.put("username", config.username);
            newConfig.put("password", config.password);

            // 将新配置写入文件
            Utils.writeString(newConfig.toJSONString(), Utils.SocksConfigFile("socks.json"), "utf-8");

            // 设置DNS over SOCKS
            String socksDnsOverSocksPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":";
            String socksDnsOverSocksSuffix = "}}}}";
            callbacks.loadConfigFromJson(socksDnsOverSocksPrefix + dns_over_socks_update + socksDnsOverSocksSuffix);

            // 设置使用用户选项
            String socksUseUserOptionsPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_user_options\":";
            String socksUseUserOptionsSuffix = "}}}}";
            callbacks.loadConfigFromJson(socksUseUserOptionsPrefix + use_user_options_update + socksUseUserOptionsSuffix);

            // 设置主机
            String socksHostPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"";
            String socksHostSuffix = "\"}}}}";
            callbacks.loadConfigFromJson(socksHostPrefix + config.ip + socksHostSuffix);

            // 设置端口
            String socksPortPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"port\":";
            String socksPortSuffix = "}}}}";
            callbacks.loadConfigFromJson(socksPortPrefix + Integer.parseInt(config.port.trim()) + socksPortSuffix);

            // 设置用户名
            String socksUsernamePrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"username\":\"";
            String socksUsernameSuffix = "\"}}}}";
            callbacks.loadConfigFromJson(socksUsernamePrefix + config.username + socksUsernameSuffix);

            // 设置密码
            String socksPasswordPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"password\":\"";
            String socksPasswordSuffix = "\"}}}}";
            callbacks.loadConfigFromJson(socksPasswordPrefix + config.password + socksPasswordSuffix);

            // 设置是否启用代理
            String socksUseProxyPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":";
            String socksUseProxySuffix = "}}}}";
            callbacks.loadConfigFromJson(socksUseProxyPrefix + enable + socksUseProxySuffix);

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

    // 开启或关闭代理
    public void isEnableSettings(IBurpExtenderCallbacks callbacks, boolean enable) {
        try{
            String jsonStr = Utils.readString(Utils.SocksConfigFile("socks.json"),"utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);

            // 更新启用状态
            jsonObject.put("use_proxy", enable);

            // 将更新后的配置写回文件
            Utils.writeString(jsonObject.toJSONString(), Utils.SocksConfigFile("socks.json"), "utf-8");

            ProxyConfig config = new ProxyConfig(
                    jsonObject.getString("host"),
                    String.valueOf(jsonObject.getInteger("port")),
                    jsonObject.getString("username"),
                    jsonObject.getString("password")
            );

            writeIpPortSettings(callbacks, config, enable);
        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    // 保存配置
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

    // 判断配置文件是否存在
    public boolean isConfigFileExist() {
        File file = new File(Utils.WORKDIR + "socks.json");
        return file.exists();
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        // 保存配置
        saveButton.addActionListener(new AbstractAction() {
            public void actionPerformed(ActionEvent evt) {
                String ipTextFieldText = ipTextField.getText();
                // 将所有的\r\n和\r都统一转换为\n
                ipTextFieldText = ipTextFieldText.replaceAll("\r\n|\r", "\n");
                String[] ipTextFieldTextSplit = ipTextFieldText.split("\n");
                proxyConfigs = new ArrayList<>();

                for (String line : ipTextFieldTextSplit) {
                    // 跳过空行
                    if (line.trim().isEmpty()) {
                        continue;
                    }

                    String[] parts = line.split(":");
                    if (parts.length >= 2) {
                        ProxyConfig config;
                        if (parts.length >= 4) {
                            // IP:PORT:USERNAME:PASSWORD 格式
                            config = new ProxyConfig(parts[0], parts[1], parts[2], parts[3]);
                        } else {
                            // IP:PORT 格式
                            config = new ProxyConfig(parts[0], parts[1], "", "");
                        }
                        proxyConfigs.add(config);
                    }
                }

                if (proxyConfigs.size() > 0) {
                    JOptionPane.showMessageDialog(null, String.format(I18nUtils.get("socks.message.save_success"), proxyConfigs.size()), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(null, I18nUtils.get("socks.message.invalid_format"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        // 切换代理
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

                currentIndex = (currentIndex + 1) % proxyConfigs.size();
                ProxyConfig currentConfig = proxyConfigs.get(currentIndex);

                String message;
                if (!currentConfig.username.isEmpty()) {
                    message = String.format(I18nUtils.get("socks.message.current_proxy_with_user"), currentConfig.ip, currentConfig.port, currentConfig.username);
                } else {
                    message = String.format(I18nUtils.get("socks.message.current_proxy"), currentConfig.ip, currentConfig.port);
                }

                JOptionPane.showMessageDialog(null, message, I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
                writeIpPortSettings(callbacks, currentConfig, enableCheckBox.isSelected());
            }
        });

        // 启用/禁用代理
        enableCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                boolean enabled = enableCheckBox.isSelected();
                isEnableSettings(callbacks, enabled);
                String currentText = logTextField.getText();
                String newText = currentText + (enabled ? "Socks Enable\n" : "Socks Disable\n");
                logTextField.setText(newText);
            }
        });

        return panel;
    }

    @Override
    public String getTabName() {
        return "SOCKS Settings";
    }
}