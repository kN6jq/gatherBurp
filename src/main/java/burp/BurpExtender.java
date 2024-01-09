package burp;

import burp.bean.ConfigBean;
import burp.menu.*;
import burp.ui.MainUI;
import burp.utils.RobotInput;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import static burp.dao.ConfigDao.getToolConfig;
import static burp.utils.Utils.writeReqFile;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IHttpListener {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.name);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.registerHttpListener(this);
        MainUI mainUI = new MainUI(Utils.callbacks);
        Utils.callbacks.addSuiteTab(mainUI);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Utils.callbacks.customizeUiComponent(mainUI);
            }
        });
        Utils.stdout.println("Loaded " + Utils.name + " v" + Utils.version + " by " + Utils.author);

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        IHttpRequestResponse[] requestResponses = iContextMenuInvocation.getSelectedMessages();
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];

        List<ConfigBean> toolParam = getToolConfig();

        for (ConfigBean config : toolParam) {
            String name = config.getType();
            String value = config.getValue();
            if (!Objects.equals(name, "") && !Objects.equals(value, "")) {
                String cmd = value;
                if (requestResponses != null) {
                    if (cmd.contains("{url}")) {
                        String url = Utils.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
                        cmd = cmd.replace("{url}", url);
                    } else if (cmd.contains("{request}")) {
                        String requestFilePath = writeReqFile(baseRequestResponse);
                        assert requestFilePath != null;
                        cmd = cmd.replace("{request}", requestFilePath);
                    } else if (cmd.contains("{host}")) {
                        String host = baseRequestResponse.getHttpService().getHost();
                        cmd = cmd.replace("{host}", host);
                    }
                }
                JMenuItem jMenuItem = new JMenuItem(name);
                String finalCmd = cmd;
                jMenuItem.addActionListener(new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Runnable toolRunner = new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    RobotInput ri = new RobotInput();
                                    ri.inputString(finalCmd);
                                } catch (Exception e1) {
                                    Utils.stderr.println(e1.getMessage());
                                }
                            }
                        };
                        new Thread(toolRunner).start();
                    }
                });
                listMenuItems.add(jMenuItem);
            }
        }
        JMenu fastjson = new JMenu("FastJson");
        fastjson.add(new FastjsonMenu().FastjsonDnslogMenu(requestResponses));
        fastjson.add(new FastjsonMenu().FastjsonEchoMenu(requestResponses));
        fastjson.add(new FastjsonMenu().FastjsonJNDIMenu(requestResponses));
        fastjson.add(new FastjsonMenu().FastjsonVersionMenu(requestResponses));
        listMenuItems.add(fastjson);
        listMenuItems.add(new AuthMenu(requestResponses));
        listMenuItems.add(new Log4jMenu(requestResponses));
        listMenuItems.add(new PermMenu(requestResponses));
        listMenuItems.add(new SqlMenu(requestResponses));
        listMenuItems.add(new Base64DataMenu(requestResponses));
        listMenuItems.add(new NucleiMenu(requestResponses));
        return listMenuItems;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest) {
            byte[] request = messageInfo.getRequest();
            String requestStr = Utils.helpers.bytesToString(request);
            if (requestStr.contains("<datab64>")) {
                String data = requestStr.substring(requestStr.indexOf("<datab64>") + 9, requestStr.indexOf("</datab64>"));
                byte[] decodedData = Base64.getDecoder().decode(data);
                byte[] newBytes = new byte[request.length - data.length() + decodedData.length];
                System.arraycopy(request, 0, newBytes, 0, requestStr.indexOf("<datab64>"));
                System.arraycopy(decodedData, 0, newBytes, requestStr.indexOf("<datab64>"), decodedData.length);
                System.arraycopy(request, requestStr.indexOf("</datab64>") + 10, newBytes, requestStr.indexOf("<datab64>") + decodedData.length, request.length - requestStr.indexOf("</datab64>") - 10);
                messageInfo.setRequest(newBytes);
            }
        }
    }
}
