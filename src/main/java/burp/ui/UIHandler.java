package burp.ui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

/** 插件内各功能面板的统一接口：由 MainUI 在 EDT 上依次 init 并挂载。 */
public interface UIHandler {
    /** 初始化面板（加载配置、构建组件）。 */
    void init();

    /** 返回面板根组件。 */
    JPanel getPanel(IBurpExtenderCallbacks callbacks);

    /** 返回标签页显示名。 */
    String getTabName();
}
