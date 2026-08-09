package burp.ui.SimilarHelper;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class TableRenderer extends DefaultTableCellRenderer {
    private static final int MAX_TEXT_LENGTH = 100;

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);

        // 隔行底色跟随当前 L&F（适配 Burp 暗色主题），运行时读取以应对主题切换
        if (!isSelected) {
            Color base = UIManager.getColor("Table.background");
            Color alt = UIManager.getColor("Table.alternateRowColor");
            if (base == null) base = Color.WHITE;
            if (alt == null) alt = base;
            c.setBackground(row % 2 == 0 ? base : alt);
        }

        if (value instanceof String) {
            String text = (String) value;
            if (text.length() > MAX_TEXT_LENGTH) {
                setText(text.substring(0, MAX_TEXT_LENGTH - 3) + "...");
                setToolTipText(text);
            } else {
                setText(text);
                setToolTipText(text);
            }
        }

        // 为特定列设置对齐方式
        if (table.getColumnName(column).equals("ID")) {
            setHorizontalAlignment(SwingConstants.CENTER);
        } else if (table.getColumnName(column).equals("Time")) {
            setHorizontalAlignment(SwingConstants.CENTER);
        } else if (table.getColumnName(column).equals("IP")) {
            setHorizontalAlignment(SwingConstants.CENTER);
        } else {
            setHorizontalAlignment(SwingConstants.LEFT);
        }

        // 设置边框
        setBorder(BorderFactory.createCompoundBorder(
                getBorder(),
                BorderFactory.createEmptyBorder(1, 4, 1, 4)
        ));

        return c;
    }
}