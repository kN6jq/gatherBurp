package burp;


import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import burp.bean.Config;
import burp.menu.*;
import burp.ui.*;
import burp.utils.*;

import static burp.dao.ConfigDAO.getToolConfig;
import static burp.utils.Utils.*;


public class BurpExtender  implements IBurpExtender, IContextMenuFactory{

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        MainUI mainUi = new MainUI(iBurpExtenderCallbacks);
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.name);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.addSuiteTab(mainUi);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Utils.callbacks.customizeUiComponent(mainUi);
            }
        });
        Utils.stdout.println("Loaded " + Utils.name + " v" + Utils.version + " by " + Utils.author);
        Utils.stdout.println("Happy Hacking :)");

    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        IHttpRequestResponse[] responses = iContextMenuInvocation.getSelectedMessages();
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];

        JMenu tools = new JMenu("tools");
        List<Config> toolParam = getToolConfig();
        for (Config config : toolParam) {
            if (!Objects.equals(config.getType(), "") && !Objects.equals(config.getValue(), "")){
                tools.add(new JMenuItem(new AbstractAction(config.getType()) {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Runnable toolRunner = new Runnable() {
                            @Override
                            public void run() {
                                try {
                                    RobotInput ri = new RobotInput();
                                    if (responses != null) {
                                        String cmd = config.getValue();
                                        if (cmd.contains("{url}")) {
                                            String url = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
                                            cmd = cmd.replace("{url}", url);
                                        } else if (cmd.contains("{request}")) {
                                            IHttpRequestResponse message = baseRequestResponse;
                                            String requestFilePath = RequestToFile(message);
                                            cmd = cmd.replace("{request}", requestFilePath);
                                        } else if (cmd.contains("{host}")) {
                                            IHttpRequestResponse message = baseRequestResponse;
                                            String host = message.getHttpService().getHost();
                                            cmd = cmd.replace("{host}", host);
                                        }
                                        ri.inputString(cmd);
                                    }
                                } catch (Exception e1) {
                                    e1.printStackTrace(stderr);
                                }
                            }
                        };
                        new Thread(toolRunner).start();
                    }
                }));
            }
        }
        listMenuItems.add(tools);
        JMenu fastjson = new JMenu("FastJson");
        fastjson.add(new FastjsonDnslogMenu(responses));
        fastjson.add(new FastjsonEchoMenu(responses));
        fastjson.add(new FastjsonJNDIMenu(responses));
        listMenuItems.add(fastjson);
        listMenuItems.add(new AuthBypassMenu(responses));
        listMenuItems.add(new PermBypassMenu(responses));
        listMenuItems.add(new SqlMenu(responses));
        listMenuItems.add(new DropHostMenu(responses));
        return listMenuItems;
    }




}