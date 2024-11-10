package burp.ui.SimilarHelper;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class TableRenderer extends DefaultTableCellRenderer {
    private static final Color ALTERNATE_COLOR = new Color(240, 240, 240);
    private static final int MAX_TEXT_LENGTH = 100;

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);

        if (!isSelected) {
            c.setBackground(row % 2 == 0 ? Color.WHITE : ALTERNATE_COLOR);
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
        } else if (table.getColumnName(column).equals("时间")) {
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