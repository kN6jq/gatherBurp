package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.FileUtils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.*;
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
    private List<String[]> ipPortPairs;
    private int currentIndex = -1; // 初始化为-1，表示没有选中任何数据


    @Override
    public void init() {
        setupUI();
        setupData();
    }

    private void setupData() {

    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        saveButton = new JButton("Save");
        panel.add(saveButton,new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        nextButton = new JButton("Next");
        panel.add(nextButton,new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        // 是否开启轮询代理的单选框
        enableCheckBox =  new JCheckBox("Enable Socks");
        panel.add(enableCheckBox,new GridBagConstraintsHelper(3, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));


        JSplitPane jSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        // 代理池文本输入框
        ipTextField = new JTextPane();
        // 设置ipTextField提示
        //ipTextField 设置边框
        ipTextField.setBorder(BorderFactory.createTitledBorder("Proxy Pool: (example 1.2.3.4:7890)"));
        ipTextField.setEditable(true);
        logTextField = new JTextPane();
        logTextField.setBorder(BorderFactory.createTitledBorder("Log"));
        logTextField.setEditable(false);
        // jSplitPane左右比例对半分
        jSplitPane.setDividerLocation(0.5);
        jSplitPane.setResizeWeight(0.5);

        jSplitPane.setLeftComponent(ipTextField);
        jSplitPane.setRightComponent(logTextField);
        panel.add(jSplitPane,new GridBagConstraintsHelper(0, 1, 0, 0).setInsets(5).setIpad(0, 0).setWeight(1.0d, 1.0d).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
    }


    // 获取配置
    public void getSettings(IBurpExtenderCallbacks callbacks) {
        String jsonStr = callbacks.saveConfigAsJson("project_options.connections.socks_proxy");
        JSONObject jsonObject = JSON.parseObject(jsonStr);
        use_proxy = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getBoolean("use_proxy");
        dns_over_socks = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getBoolean("dns_over_socks");
        use_user_options = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getBoolean("use_user_options");
        host = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getString("host");
        password = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getString("password");
        port = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getInteger("port");
        username = jsonObject.getJSONObject("project_options").getJSONObject("connections").getJSONObject("socks_proxy").getString("username");
        Utils.stdout.println(jsonObject.toJSONString());
    }

    // 加载配置
    public void loadSettings(IBurpExtenderCallbacks callbacks) {
        try{
            String jsonStr = FileUtils.readFileToString(Utils.SocksConfigFile("socks.json"), "utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            boolean use_proxy_update = jsonObject.getBoolean("use_proxy");
            boolean dns_over_socks_update = jsonObject.getBoolean("dns_over_socks");
            boolean use_user_options_update = jsonObject.getBoolean("use_user_options");
            String host_update = jsonObject.getString("host");
            int port_update = jsonObject.getInteger("port");
            String username_update = jsonObject.getString("username");
            String password_update = jsonObject.getString("password");

            String socksDnsOverSocksPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":";
            String socksDnsOverSocksSuffix = "}}}}";
            String reconstitutedsocksDnsOverSocks = socksDnsOverSocksPrefix + dns_over_socks_update + socksDnsOverSocksSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksDnsOverSocks);

            String socksUseUserOptionsPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_user_options\":";
            String socksUseUserOptionsSuffix = "}}}}";
            String reconstitutedsocksUseUserOptions = socksUseUserOptionsPrefix + use_user_options_update + socksUseUserOptionsSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseUserOptions);

            String socksHostPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"";
            String socksHostSuffix = "\"}}}}";
            String reconstitutedsocksHost = socksHostPrefix + host_update + socksHostSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksHost);

            String socksPortPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"port\":";
            String socksPortSuffix = "}}}}";
            String reconstitutedsocksPort = socksPortPrefix + port_update + socksPortSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPort);

            String socksUsernamePrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"username\":\"";
            String socksUsernameSuffix = "\"}}}}";
            String reconstitutedsocksUsername = socksUsernamePrefix + username_update + socksUsernameSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUsername);

            String socksPasswordPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"password\":\"";
            String socksPasswordSuffix = "\"}}}}";
            String reconstitutedsocksPassword = socksPasswordPrefix + password_update + socksPasswordSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPassword);


            String socksUseProxyPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":";
            String socksUseProxySuffix = "}}}}";
            String reconstitutedsocksUseProxy = socksUseProxyPrefix + use_proxy_update + socksUseProxySuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseProxy);

            Utils.stdout.println("SOCKS Settings Loaded");
            Utils.stdout.println(jsonStr);
        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    // 写数据
    public void writeIpPortSettings(IBurpExtenderCallbacks callbacks,String ip,String port,boolean enable) {
        // port转为int
        int port_update = Integer.parseInt(port.trim());

        if (!isConfigFileExist()){
            saveSettings(callbacks);
        }

        try{
            String jsonStr = FileUtils.readFileToString(Utils.SocksConfigFile("socks.json"), "utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            boolean dns_over_socks_update = jsonObject.getBoolean("dns_over_socks");
            boolean use_user_options_update = jsonObject.getBoolean("use_user_options");
            String username_update = jsonObject.getString("username");
            String password_update = jsonObject.getString("password");

            String socksDnsOverSocksPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":";
            String socksDnsOverSocksSuffix = "}}}}";
            String reconstitutedsocksDnsOverSocks = socksDnsOverSocksPrefix + dns_over_socks_update + socksDnsOverSocksSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksDnsOverSocks);

            String socksUseUserOptionsPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_user_options\":";
            String socksUseUserOptionsSuffix = "}}}}";
            String reconstitutedsocksUseUserOptions = socksUseUserOptionsPrefix + use_user_options_update + socksUseUserOptionsSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseUserOptions);

            String socksHostPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"";
            String socksHostSuffix = "\"}}}}";
            String reconstitutedsocksHost = socksHostPrefix + ip + socksHostSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksHost);

            String socksPortPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"port\":";
            String socksPortSuffix = "}}}}";
            String reconstitutedsocksPort = socksPortPrefix + port_update + socksPortSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPort);

            String socksUsernamePrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"username\":\"";
            String socksUsernameSuffix = "\"}}}}";
            String reconstitutedsocksUsername = socksUsernamePrefix + username_update + socksUsernameSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUsername);

            String socksPasswordPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"password\":\"";
            String socksPasswordSuffix = "\"}}}}";
            String reconstitutedsocksPassword = socksPasswordPrefix + password_update + socksPasswordSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPassword);


            String socksUseProxyPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":";
            String socksUseProxySuffix = "}}}}";
            String reconstitutedsocksUseProxy = socksUseProxyPrefix + enable + socksUseProxySuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseProxy);

            String currentText = logTextField.getText();
            String newText = currentText +"Socks Setting Success \n"+ "Current ip :" +ip+" port: "+ port +" \n"; // 使用\\n来换行
            logTextField.setText(newText);

        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    // 开启或关闭代理
    public void isEnableSettings(IBurpExtenderCallbacks callbacks,boolean enable) {
        if (!isConfigFileExist()){
            saveSettings(callbacks);
        }
        try{
            String jsonStr = FileUtils.readFileToString(Utils.SocksConfigFile("socks.json"), "utf-8");
            JSONObject jsonObject = JSON.parseObject(jsonStr);
            boolean dns_over_socks_update = jsonObject.getBoolean("dns_over_socks");
            boolean use_user_options_update = jsonObject.getBoolean("use_user_options");
            String host_update = jsonObject.getString("host");
            int port_update = jsonObject.getInteger("port");
            String username_update = jsonObject.getString("username");
            String password_update = jsonObject.getString("password");

            String socksDnsOverSocksPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"dns_over_socks\":";
            String socksDnsOverSocksSuffix = "}}}}";
            String reconstitutedsocksDnsOverSocks = socksDnsOverSocksPrefix + dns_over_socks_update + socksDnsOverSocksSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksDnsOverSocks);

            String socksUseUserOptionsPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_user_options\":";
            String socksUseUserOptionsSuffix = "}}}}";
            String reconstitutedsocksUseUserOptions = socksUseUserOptionsPrefix + use_user_options_update + socksUseUserOptionsSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseUserOptions);

            String socksHostPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"host\":\"";
            String socksHostSuffix = "\"}}}}";
            String reconstitutedsocksHost = socksHostPrefix + host_update + socksHostSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksHost);

            String socksPortPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"port\":";
            String socksPortSuffix = "}}}}";
            String reconstitutedsocksPort = socksPortPrefix + port_update + socksPortSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPort);

            String socksUsernamePrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"username\":\"";
            String socksUsernameSuffix = "\"}}}}";
            String reconstitutedsocksUsername = socksUsernamePrefix + username_update + socksUsernameSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUsername);

            String socksPasswordPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"password\":\"";
            String socksPasswordSuffix = "\"}}}}";
            String reconstitutedsocksPassword = socksPasswordPrefix + password_update + socksPasswordSuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksPassword);


            String socksUseProxyPrefix = "{\"project_options\":{\"connections\":{\"socks_proxy\":{\"use_proxy\":";
            String socksUseProxySuffix = "}}}}";
            String reconstitutedsocksUseProxy = socksUseProxyPrefix + enable + socksUseProxySuffix;
            callbacks.loadConfigFromJson(reconstitutedsocksUseProxy);

        }catch (Exception e2){
            Utils.stderr.println(e2.getMessage());
        }
    }

    // 保存配置
    public void saveSettings(IBurpExtenderCallbacks callbacks) {
        // 创建Fastjson的JSONObject
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("use_proxy", use_proxy);
        jsonObject.put("use_user_options", use_user_options);
        jsonObject.put("dns_over_socks", dns_over_socks);
        jsonObject.put("host", host);
        jsonObject.put("port", port);
        jsonObject.put("username", username);
        jsonObject.put("password", password);
        // 将JSONObject转换为JSON字符串
        String sockinfo = jsonObject.toJSONString();
        try{
            FileUtils.write(Utils.SocksConfigFile("socks.json"),sockinfo,"utf-8");
        }catch (Exception e){
            Utils.stderr.println(e.getMessage());
        }
    }

    // 判断配置文件是否存在
    public boolean isConfigFileExist() {
        File file = new File(Utils.workdir + "socks.json");
        return file.exists();
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {


        // 保存按钮
        saveButton.addActionListener(new AbstractAction() {
            public void actionPerformed(ActionEvent evt) {
//                ipPortPairs.clear();
                String ipTextFieldText = ipTextField.getText();
                String[] ipTextFieldTextSplit = ipTextFieldText.split("\n");
                ipPortPairs = new ArrayList<>();
                for (String ipPortPair : ipTextFieldTextSplit) {
                    String[] parts = ipPortPair.split(":");
                    ipPortPairs.add(parts);
                }
                // 弹出提示框
                if (ipPortPairs.size() > 0) {
                    JOptionPane.showMessageDialog(null, "成功保存数据"+ipPortPairs.size()+"条", "提示", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(null, "请输入IP:PORT", "提示", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        // 切换ip
        nextButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (currentIndex >= 0 && currentIndex < ipPortPairs.size()) {
                    // 删除上一次选中的数据
                    ipPortPairs.remove(currentIndex);
                }
                // 更新索引为下一次点击的数据
                currentIndex = (currentIndex + 1) % ipPortPairs.size();
                // 获取当前数据并显示
                String[] currentData = ipPortPairs.get(currentIndex);
                // 弹出提示框
                if (currentData != null && currentData.length == 2) {
                    String ip = currentData[0];
                    String port = currentData[1];
                    if (enableCheckBox.isSelected()){
                        JOptionPane.showMessageDialog(null, "当前使用ip:"+ip+":"+port, "提示", JOptionPane.INFORMATION_MESSAGE);
                        writeIpPortSettings(callbacks,ip,port,true);
                    }else {
                        JOptionPane.showMessageDialog(null, "当前使用ip:"+ip+":"+port, "提示", JOptionPane.INFORMATION_MESSAGE);
                        writeIpPortSettings(callbacks,ip,port,false);
                    }

                }else{
                    JOptionPane.showMessageDialog(null, "输入数据不合法", "提示", JOptionPane.INFORMATION_MESSAGE);
                }

            }
        });

        // 开启
        enableCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (enableCheckBox.isSelected()){
                    isEnableSettings(callbacks,true);
                    String currentText = logTextField.getText();
                    String newText = currentText + "Socks Enable\n"; // 使用\\n来换行
                    logTextField.setText(newText);

                }else {
                    isEnableSettings(callbacks,false);
                    String currentText = logTextField.getText();
                    String newText = currentText + "Socks Disable\n"; // 使用\\n来换行
                    logTextField.setText(newText);
                }
            }
        });

        return panel;
    }

    @Override
    public String getTabName() {
        return "SOCKS Settings";
    }
}
