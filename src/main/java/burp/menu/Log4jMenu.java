package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.Log4jUI;

/** Log4j 右键菜单：对选中请求发起主动 JNDI 注入探测。 */
public class Log4jMenu extends AbstractScanMenu {
    public Log4jMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Log4j Check", requestResponses);
    }

    @Override
    protected void doScan() {
        Log4jUI.Check(requestResponses, true);
    }
}
