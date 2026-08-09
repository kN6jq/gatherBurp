package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;

public class AuthMenu extends AbstractScanMenu {
    public AuthMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ AuthBypass Check", requestResponses);
    }

    @Override
    protected void doScan() {
        AuthUI.Check(requestResponses);
    }
}
