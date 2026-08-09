package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class RouteCustomTableCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value instanceof String) {
            String text = (String) value;
            // 选中时沿用选中前景色（避免暗色选中背景下绿/红字不可读）；未选中时用语义色
            if (!isSelected) {
                if (I18nUtils.get("route.value.enabled").equals(text)) {
                    setForeground(Color.GREEN);
                } else if (I18nUtils.get("route.value.disabled").equals(text)) {
                    setForeground(Color.RED);
                }
            }
        }
        return this;
    }
}
