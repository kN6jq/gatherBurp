package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.SqlUI;

/** SQL 注入右键菜单：对选中请求发起主动 payload 探测。 */
public class SqlMenu extends AbstractScanMenu {
    public SqlMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Sql Check", requestResponses);
    }

    @Override
    protected void doScan() {
        SqlUI.Check(requestResponses, true);
    }
}
