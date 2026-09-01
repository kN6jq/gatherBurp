package burp.ui.SimilarHelper;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/** Similar 模块表格通用单元格渲染器：隔行底色运行时读取 L&F 颜色（适配 Burp 暗色主题与切换）、
 *  超长文本截断（完整值进 tooltip）、ID/Time/IP 列居中。渲染器实例被 Swing 复用，勿在其中持有行状态。 */
public class TableRenderer extends DefaultTableCellRenderer {
    // 超过该长度截断显示，完整内容放 tooltip
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