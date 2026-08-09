package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.Log4jUI;

public class Log4jMenu extends AbstractScanMenu {
    public Log4jMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Log4j Check", requestResponses);
    }

    @Override
    protected void doScan() {
        Log4jUI.Check(requestResponses, true);
    }
}
