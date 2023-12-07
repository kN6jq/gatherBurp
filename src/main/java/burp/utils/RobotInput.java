package burp.utils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

public class RobotInput extends Robot {
    public RobotInput() throws AWTException {
        super();
    }

    public void inputString(String str) {
        delay(100);
        Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();//获取剪切板
        StringSelection tText = new StringSelection(str);
        clip.setContents(tText, tText); //设置剪切板内容,在Linux中这会修改ctrl+shift+v的内容
        delay(100);
    }
}
