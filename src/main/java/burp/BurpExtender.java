package burp;

import burp.bean.ConfigBean;
import burp.menu.*;
import burp.ui.MainUI;
import burp.utils.RobotInput;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.*;

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
        Utils.stdout.println("If a database error is reported, please manually delete the ./gather/ directory of the username directory and try\n");
        Utils.stdout.println("GITHUB: https://github.com/kN6jq/gatherBurp");

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        IHttpRequestResponse[] requestResponses = iContextMenuInvocation.getSelectedMessages();
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];
        // 如果是个空的, 则返回null
        if (baseRequestResponse.getHttpService() == null) {
            return null;
        }
        List<ConfigBean> toolParam = getToolConfig();
        for (ConfigBean config : toolParam) {
            String name = config.getType();
            String value = config.getValue();
            if (!name.isEmpty() && !value.isEmpty()) {
                JMenuItem jMenuItem = new JMenuItem(name);
                jMenuItem.addActionListener(new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (value.contains("{url}")){
                            String url = Utils.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
                            try {
                                RobotInput ri = new RobotInput();
                                ri.inputString(value.replace("{url}", url));
                            } catch (Exception ex) {
                                Utils.stderr.println(ex.getMessage());
                            }
                        }else if (value.contains("{host}")) {
                            String host = baseRequestResponse.getHttpService().getHost();
                            try {
                                RobotInput ri = new RobotInput();
                                ri.inputString(value.replace("{host}", host));
                            } catch (Exception ex) {
                                Utils.stderr.println(ex.getMessage());
                            }
                        } else if (value.contains("{request}")) {
                            String requestFilePath = writeReqFile(baseRequestResponse);
                            if (requestFilePath != null) {
                                try {
                                    RobotInput ri = new RobotInput();
                                    ri.inputString(value.replace("{request}", requestFilePath));
                                } catch (Exception ex) {
                                    Utils.stderr.println(ex.getMessage());
                                }
                            } else {
                                Utils.stderr.println("Failed to write request file.");
                            }
                        }
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

        listMenuItems.add(new SqlMenu(requestResponses));
        listMenuItems.add(new AuthMenu(requestResponses));
        listMenuItems.add(new RouteMenu(requestResponses));
        listMenuItems.add(new Log4jMenu(requestResponses));
        listMenuItems.add(new PermMenu(requestResponses));
        listMenuItems.add(new Base64DataMenu());
        listMenuItems.add(new DirtyMenu());
        listMenuItems.add(new NucleiMenu(requestResponses));
        return listMenuItems;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest) {
            byte[] request = messageInfo.getRequest();
            String requestStr = Utils.helpers.bytesToString(request);
            if (requestStr.contains("<datab64>")) {
                // 解码 base64 数据
                String data = requestStr.substring(requestStr.indexOf("<datab64>") + 9, requestStr.indexOf("</datab64>"));
                byte[] decodedData = Base64.getDecoder().decode(data);

                // 构建新的请求体
                byte[] newBytes = new byte[requestStr.indexOf("<datab64>") + decodedData.length + (request.length - requestStr.indexOf("</datab64>") - 10)];
                System.arraycopy(request, 0, newBytes, 0, requestStr.indexOf("<datab64>"));
                System.arraycopy(decodedData, 0, newBytes, requestStr.indexOf("<datab64>"), decodedData.length);
                System.arraycopy(request, requestStr.indexOf("</datab64>") + 10, newBytes, requestStr.indexOf("<datab64>") + decodedData.length, request.length - requestStr.indexOf("</datab64>") - 10);

                // 更新 Content-Length
                IRequestInfo analyzedRequest = Utils.helpers.analyzeRequest(newBytes);
                List<String> headers = new ArrayList<>(analyzedRequest.getHeaders());
                int bodyOffset = analyzedRequest.getBodyOffset();
                int contentLength = newBytes.length - bodyOffset;

                // 更新或添加 Content-Length 头
                boolean contentLengthFound = false;
                for (int i = 0; i < headers.size(); i++) {
                    if (headers.get(i).startsWith("Content-Length:")) {
                        headers.set(i, "Content-Length: " + contentLength);
                        contentLengthFound = true;
                        break;
                    }
                }
                if (!contentLengthFound) {
                    headers.add("Content-Length: " + contentLength);
                }

                // 重建请求
                byte[] body = new byte[newBytes.length - bodyOffset];
                System.arraycopy(newBytes, bodyOffset, body, 0, body.length);
                byte[] updatedRequest = Utils.helpers.buildHttpMessage(headers, body);

                messageInfo.setRequest(updatedRequest);
            }
        }
    }

}
