package burp;


import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import burp.bean.Config;
import burp.menu.*;
import burp.ui.*;
import burp.utils.*;

import static burp.dao.ConfigDAO.getToolConfig;
import static burp.utils.Utils.*;


public class BurpExtender  implements IBurpExtender, IContextMenuFactory,IHttpListener{

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        MainUI mainUi = new MainUI(iBurpExtenderCallbacks);
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.name);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.registerHttpListener(this);
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
        listMenuItems.add(new Log4jCheckMenu(responses));
        listMenuItems.add(new DropHostMenu(responses));
        listMenuItems.add(new Base64DataMenu(responses));
        return listMenuItems;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
//        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest){
//            IHttpRequestResponse[] baseRequestResponse = new IHttpRequestResponse[]{messageInfo};
//            IHttpRequestResponse iHttpRequestResponse = baseRequestResponse[0];
//            IRequestInfo iRequestInfo = helpers.analyzeRequest(baseRequestResponse[0]);
//            String request = Utils.helpers.bytesToString(iHttpRequestResponse.getRequest());
//            String method = iRequestInfo.getMethod();
//            String body = new String(messageInfo.getRequest());
//            if (method.equals("POST")){
//                // 获取当前时间
//                long time = System.currentTimeMillis();
//                if (body.contains("<base64data>") && body.contains("</base64data>")){
//                    String data = body.substring(body.indexOf("<base64data>")+12,body.indexOf("</base64data>"));
//                    byte[] decodedData = Base64.getDecoder().decode(data);
//                    // 创建一个新的byte数组来存储替换后的数据
//                    byte[] newBytes = new byte[request.length() - data.length() + decodedData.length];
//                    // 将request的前部分拷贝到新数组中
//                    System.arraycopy(request.getBytes(), 0, newBytes, 0, body.indexOf("<base64data>"));
//                    // 将解码后的数据拷贝到新数组中
//                    System.arraycopy(decodedData, 0, newBytes, body.indexOf("<base64data>"), decodedData.length);
//                    // 将request的后部分拷贝到新数组中
//                    System.arraycopy(request.getBytes(), body.indexOf("</base64data>") + 13, newBytes, body.indexOf("<base64data>") + decodedData.length, request.length() - body.indexOf("</base64data>") - 13);
//                    Utils.stdout.println(System.currentTimeMillis()-time);
//                    Utils.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(),newBytes );
//                }
//            }
//
//        }
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && messageIsRequest){
            byte[] request = messageInfo.getRequest();
            String requestStr = helpers.bytesToString(request);
            if (requestStr.contains("<datab64>")){
                String data = requestStr.substring(requestStr.indexOf("<datab64>")+9,requestStr.indexOf("</datab64>"));
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