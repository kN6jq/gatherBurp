package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.PermUI;

public class PermMenu extends AbstractScanMenu {
    public PermMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Perm Check", requestResponses);
    }

    @Override
    protected void doScan() {
        PermUI.Check(requestResponses, true);
    }
}
