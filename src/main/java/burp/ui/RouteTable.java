package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;

/** 目录探测规则表格（RouteUI 左栏）：规则列表 + 启用状态展示，全列可排序。 */
public class RouteTable extends JTable {
    /** 启用状态配色：深浅主题下都足够醒目。 */
    private static final Color ENABLED_GREEN = new Color(0x2ECC71);
    private static final Color DISABLED_RED = new Color(0xE74C3C);

    public RouteTable(TableModel tableModel) {
        super(tableModel);
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        // enable 列要完整放下 "Enabled"/"Disabled"
        columnModel.getColumn(1).setMinWidth(70);
        columnModel.getColumn(1).setMaxWidth(85);
        columnModel.getColumn(2).setMinWidth(100);
        columnModel.getColumn(2).setMaxWidth(180);
        // 启用状态着色：开启绿、关闭红（值与模型同源，取自同一 i18n 键，切换语言后仍然成立）
        columnModel.getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component component = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                component.setForeground(isEnabledValue(value) ? ENABLED_GREEN : DISABLED_RED);
                return component;
            }
        });
        // 全列可排序：Enable/Disable/Delete 按钮已用 convertRowIndexToModel 取行，
        // 视图排序不影响其定位到正确的底层规则
        TableRowSorter<TableModel> sorter = new TableRowSorter<>(tableModel);
        // Enable 列按底层状态排序（关闭=0 < 开启=1），显示文本的字典序在中英文下都不可靠
        sorter.setComparator(1, (a, b) -> Boolean.compare(isEnabledValue(a), isEnabledValue(b)));
        // ID 列按数字排序，避免 "10" 排到 "2" 前面
        sorter.setComparator(0, (a, b) -> Integer.compare(parseId(a), parseId(b)));
        setRowSorter(sorter);
    }

    /** 判断显示值是否为"开启"状态（与模型取值同源，中英文文案均成立）。 */
    static boolean isEnabledValue(Object value) {
        return value != null && I18nUtils.get("route.value.enabled").equals(value);
    }

    private static int parseId(Object value) {
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
