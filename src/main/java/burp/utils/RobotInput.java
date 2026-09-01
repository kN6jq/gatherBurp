package burp.utils;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

/** 动态工具命令的输入模拟：把命令文本写入系统剪贴板并提示用户手动粘贴执行（Robot 保留以维持构造副作用）。 */
public class RobotInput extends Robot {

    public RobotInput() throws AWTException {
        super();
    }

    /** 设置剪贴板内容；首次调用弹粘贴提示（Utils.isSelect 只提示一次）。 */
    public void inputString(String str) {
        delay(100);
        Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();//获取剪切板
        StringSelection tText = new StringSelection(str);
        clip.setContents(tText, tText); //设置剪切板内容,在Linux中这会修改ctrl+shift+v的内容
        delay(100);
        if (!Utils.isSelect){
            Utils.isSelect = true;
            JOptionPane.showMessageDialog(null, I18nUtils.get("robot.message.paste_tip"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
