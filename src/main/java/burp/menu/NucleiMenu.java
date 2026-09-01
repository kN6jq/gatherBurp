package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.Nuclei;
import burp.utils.ScanTaskExecutor;

import javax.swing.*;

/** Nuclei 模板生成右键菜单：把选中请求转换为 Nuclei 模板文本（异步执行）。 */
public class NucleiMenu extends JMenuItem {
    public NucleiMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Nuclei Template");
        addActionListener(e -> ScanTaskExecutor.execute(
                "Nuclei template generation", () -> Nuclei.Generate(requestResponses)));
    }
}
