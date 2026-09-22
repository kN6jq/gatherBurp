package burp.ui.codec;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

/** U2C 页签工厂：注册后每个消息编辑器（Repeater/Proxy 等）都带一个 U2C 附属页签。 */
public class U2CTabFactory implements IMessageEditorTabFactory {
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new U2CTab(controller, editable);
    }
}
