package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;

/** 目录穿越（AuthBypass）右键菜单：对选中请求发起前/后缀变异探测。 */
public class AuthMenu extends AbstractScanMenu {
    public AuthMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ AuthBypass Check", requestResponses);
    }

    @Override
    protected void doScan() {
        AuthUI.Check(requestResponses);
    }
}
