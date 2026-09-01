package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.ScanTaskExecutor;
import javax.swing.*;

/** 扫描模块右键菜单基类：菜单在 EDT 构建，点击后把 doScan 提交到 ScanTaskExecutor 池执行
 *  （doScan 内部不得再碰 Swing 组件，刷新统一经 invokeLater）。 */
public abstract class AbstractScanMenu extends JMenuItem {
    protected final IHttpRequestResponse[] requestResponses;

    /** 构造函数：设置菜单显示名并绑定扫描请求。 */
    public AbstractScanMenu(String name, IHttpRequestResponse[] requestResponses) {
        super(name);
        this.requestResponses = requestResponses;
        this.addActionListener(e -> ScanTaskExecutor.execute(
                getScanName() + " manual scan", this::doScan));
    }

    /** 实际扫描动作，运行在 ScanTaskExecutor 池线程。 */
    protected abstract void doScan();

    /** 返回扫描名称（去掉 Menu 后缀），用于线程池任务标识。 */
    protected String getScanName() {
        return getClass().getSimpleName().replace("Menu", "");
    }
}
