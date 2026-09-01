package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.PermUI;

/** 越权（Perm）右键菜单：对选中请求发起原始/低权限/无权限三态对比探测。 */
public class PermMenu extends AbstractScanMenu {
    public PermMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Perm Check", requestResponses);
    }

    @Override
    protected void doScan() {
        PermUI.Check(requestResponses, true);
    }
}
