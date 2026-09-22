package burp.ui.SimilarHelper;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.HashSet;
import java.util.Set;

/** Similar 模块表格通用单元格渲染器：隔行底色运行时读取 L&F 颜色（适配 Burp 暗色主题与切换）、
 *  超长文本截断（完整值进 tooltip）、构造时传入的列（ID/Time/IP 等短值列）居中。
 *  渲染器实例被 Swing 复用，勿在其中持有行状态；边框每轮重绘都从固定基准重建，
 *  不能在 getBorder() 基础上叠加——那会让复合边框随重绘次数无限套娃。 */
public class TableRenderer extends DefaultTableCellRenderer {
    // 超过该长度截断显示，完整内容放 tooltip
    private static final int MAX_TEXT_LENGTH = 100;
    private static final Border CELL_PADDING = BorderFactory.createEmptyBorder(1, 4, 1, 4);

    // 需要居中显示的列索引（列名随语言切换，按索引判断才可靠）
    private final Set<Integer> centeredColumns;

    public TableRenderer(int... centeredColumns) {
        this.centeredColumns = new HashSet<>();
        for (int column : centeredColumns) {
            this.centeredColumns.add(column);
        }
    }

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

        setHorizontalAlignment(centeredColumns.contains(column)
                ? SwingConstants.CENTER : SwingConstants.LEFT);

        // 从固定基准重建边框（聚焦高亮保留在里层），叠加会随重绘次数线性增长
        Border base = hasFocus
                ? UIManager.getBorder("Table.focusCellHighlightBorder")
                : null;
        setBorder(base == null
                ? CELL_PADDING
                : BorderFactory.createCompoundBorder(base, CELL_PADDING));

        return c;
    }
}
