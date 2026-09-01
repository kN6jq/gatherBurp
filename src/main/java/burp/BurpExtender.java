package burp;

import burp.bean.ConfigBean;
import burp.menu.*;
import burp.ui.MainUI;
import burp.ui.SimilarUI;
import burp.ui.SqlUI;
import burp.ui.SimilarHelper.ThreadManager;
import burp.utils.DbUtils;
import burp.utils.RobotInput;
import burp.utils.ScanTaskExecutor;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.*;

import static burp.dao.ConfigDao.getToolConfig;
import static burp.utils.Utils.writeReqFile;

/**
 * 插件入口：沿用 Burp legacy 扩展 API（IBurpExtenderCallbacks，未迁移 Montoya 为长期项）。
 *
 * <p>生命周期：registerExtenderCallbacks（插件加载，初始化线程池/数据库/UI/各监听器）→
 * processHttpMessage（代理监听线程，每条消息回调）/ createMenuItems（EDT，右键菜单构建）→
 * extensionUnloaded（卸载，依次关停 SimilarUI、扫描池与 Similar 线程池）。</p>
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, IHttpListener, IExtensionStateListener {
    /** 插件加载时执行（Burp 扩展线程）：启动扫描池 → 注入全局回调 → 初始化 SQLite → 挂载主 UI 与各监听器。
     *  顺序约束：DbUtils.init 先于任何 UI 的构造（UI 构造即读配置表）。 */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        ScanTaskExecutor.start();
        Utils.callbacks = iBurpExtenderCallbacks;
        Utils.helpers = iBurpExtenderCallbacks.getHelpers();
        Utils.stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        Utils.stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        Utils.callbacks.setExtensionName(Utils.NAME);
        Utils.callbacks.registerContextMenuFactory(this);
        Utils.callbacks.registerHttpListener(this);
        Utils.callbacks.registerExtensionStateListener(this);
        DbUtils.init();
        MainUI mainUI = new MainUI(Utils.callbacks);
        Utils.callbacks.addSuiteTab(mainUI);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Utils.callbacks.customizeUiComponent(mainUI);
            }
        });
        Utils.stdout.println("[" + Utils.NAME + " v" + Utils.VERSION + "] by " + Utils.AUTHOR + " loaded successfully.\n");
        Utils.stdout.println("Tip: If any errors occur, delete the '.gather' directory in your user folder and reload the extension.\n");
        Utils.stdout.println("GitHub: https://github.com/kN6jq/gatherBurp\n");

    }

    /** 右键菜单构建（EDT）：无选中消息时返回 null（菜单整体不显示）；
     *  含 config 表 module=tool 的动态命令菜单（值支持 {url}/{host}/{request} 占位符，经 RobotInput 键入）
     *  与 FastJson/SQL/AuthBypass/Route/Log4j/Perm/Nuclei/工具 固定菜单。 */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>(1);
        if (iContextMenuInvocation == null) {
            return null;
        }
        IHttpRequestResponse[] requestResponses = iContextMenuInvocation.getSelectedMessages();
        if (requestResponses == null || requestResponses.length == 0 || requestResponses[0] == null) {
            return null;
        }
        IHttpRequestResponse baseRequestResponse = requestResponses[0];
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
        fastjson.add(FastjsonMenu.FastjsonDnslogMenu(requestResponses));
        fastjson.add(FastjsonMenu.FastjsonEchoMenu(requestResponses));
        fastjson.add(FastjsonMenu.FastjsonJNDIMenu(requestResponses));
        fastjson.add(FastjsonMenu.FastjsonVersionMenu(requestResponses));
        listMenuItems.add(fastjson);

        listMenuItems.add(new SqlMenu(requestResponses));
        listMenuItems.add(new AuthMenu(requestResponses));
        listMenuItems.add(new RouteMenu(requestResponses));
        listMenuItems.add(new Log4jMenu(requestResponses));
        listMenuItems.add(new PermMenu(requestResponses));
        listMenuItems.add(new NucleiMenu(requestResponses));
        listMenuItems.add(new TextProcessMenu(iContextMenuInvocation));
        return listMenuItems;
    }


    /** 插件卸载：关停三个后台执行器，避免线程泄漏到下一加载周期。 */
    @Override
    public void extensionUnloaded() {
        SimilarUI.shutdown();
        ScanTaskExecutor.shutdown();
        ThreadManager.shutdown();
    }

    /** 消息回调，运行在 Burp 代理监听线程（非 EDT）：
     *  ① 分发 SQL 被动扫描（统一入口，内部过滤开关/方向/工具来源）；
     *  ② Repeater 请求中的 {@code <datab64>…</datab64>} 标签就地解码并同步 Content-Length。 */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 统一入口：SQL 模块不再单独注册 IHttpListener，避免被动扫描依赖 UI 初始化/注册时序。
        // 该调用内部会过滤开关、请求/响应方向以及 Burp 工具来源。
        SqlUI.dispatchPassiveHttpMessage(toolFlag, messageIsRequest, messageInfo);

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
