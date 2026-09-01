package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.RouteUI;

/** 目录探测（Route）右键菜单：对选中请求发起主动规则探测。 */
public class RouteMenu extends AbstractScanMenu {
    public RouteMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Route Check", requestResponses);
    }

    @Override
    protected void doScan() {
        RouteUI.Check(requestResponses, true);
    }
}
