package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.FastjsonUI;

import javax.swing.*;

/** Fastjson 系列右键菜单：按检测类型（dnslog/echo/JNDI/version）分别提供入口，
 *  各菜单在 ScanTaskExecutor 池线程调用对应 FastjsonUI 检测。 */
public abstract class FastjsonMenu extends AbstractScanMenu {
    private FastjsonMenu(IHttpRequestResponse[] requestResponses, String name) {
        super(name, requestResponses);
    }

    /** 创建 Dnslog 检测菜单项。 */
    public static JMenuItem FastjsonDnslogMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Dnslog Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckDnslog(requestResponses);
            }
        };
    }

    /** 创建回显检测菜单项。 */
    public static JMenuItem FastjsonEchoMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Echo Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckEchoVul(requestResponses);
            }
        };
    }

    /** 创建 JNDI 注入检测菜单项。 */
    public static JMenuItem FastjsonJNDIMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson JNDI Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckJNDIVul(requestResponses);
            }
        };
    }

    /** 创建 Fastjson 版本探测菜单项。 */
    public static JMenuItem FastjsonVersionMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Version Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckVersion(requestResponses);
            }
        };
    }
}
