package burp.ui.codec;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.ITextEditor;
import burp.utils.CodecUtils;
import burp.utils.I18nUtils;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/** 消息编辑器 U2C 附属页签：把请求/响应里的 Unicode 转义转成中文显示，可在候选编码间轮换重显。
 *  每次切换都从原始字节按所选编码重新解释（不叠加转换）；只读展示，getMessage 恒返原始内容。 */
public class U2CTab implements IMessageEditorTab {
    private final ITextEditor textEditor;
    private final JPanel panel;
    private final JButton changeEncodingButton;
    private byte[] originContent;
    private boolean isRequest;
    private List<String> charsetCandidates;
    private int charsetIndex = 0;

    public U2CTab(IMessageEditorController controller, boolean editable) {
        textEditor = Utils.callbacks.createTextEditor();
        textEditor.setEditable(editable);
        panel = new JPanel(new BorderLayout());
        changeEncodingButton = new JButton();
        changeEncodingButton.addActionListener(e -> {
            charsetIndex = (charsetIndex + 1) % charsetCandidates.size();
            display();
        });
        panel.add(changeEncodingButton, BorderLayout.NORTH);
        panel.add(textEditor.getComponent(), BorderLayout.CENTER);
    }

    private String currentCharset() {
        return charsetCandidates.get(charsetIndex);
    }

    @Override
    public String getTabCaption() {
        return I18nUtils.get("u2c.tab.caption");
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.isRequest = isRequest;
        originContent = content;
        charsetCandidates = CodecUtils.buildCharsetCandidates(content);
        charsetIndex = 0;
        display();
    }

    /** 按当前候选编码从原始字节重建显示内容并刷新按钮文案。 */
    private void display() {
        String charset = currentCharset();
        String caption = String.format(I18nUtils.get("u2c.button.change_encoding"), charset);
        if (originContent == null) {
            textEditor.setText(I18nUtils.get("u2c.message.nothing_to_show").getBytes());
            changeEncodingButton.setText(caption);
            return;
        }
        byte[] displayBytes = CodecUtils.buildDisplayContent(originContent, isRequest, charset);
        textEditor.setText(CodecUtils.convertCharset(displayBytes, charset, CodecUtils.SYSTEM_CHARSET));
        changeEncodingButton.setText(caption);
    }

    @Override
    public byte[] getMessage() {
        return originContent;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return textEditor.getSelectedText();
    }
}
