package burp.ui.SimilarHelper;

import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import java.util.Arrays;
import java.util.List;

public class OptimizedDomainTable extends JTable {
    private final OptimizedTableModel model;

    public OptimizedDomainTable() {
        model = new OptimizedTableModel(
                new String[]{"ID", "域名", "IP", "时间"},
                1  // 域名列作为唯一键
        );
        setModel(model);

        // 设置渲染器
        setDefaultRenderer(Object.class, new OptimizedTableRenderer());

        // 设置列宽
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(50);
        columnModel.getColumn(1).setPreferredWidth(200);
        columnModel.getColumn(2).setPreferredWidth(100);
        columnModel.getColumn(3).setPreferredWidth(150);

        // 优化表格属性
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setRowHeight(20);

        // 开启表格排序
        setAutoCreateRowSorter(true);

        // 双缓冲提高渲染性能
        setDoubleBuffered(true);
    }

    public void addEntry(DomainEntry entry) {
        if (entry == null || entry.getDomain() == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                List<Object> rowData = Arrays.asList(
                        entry.getId(),
                        entry.getDomain(),
                        entry.getIp(),
                        entry.getTimestamp()
                );
                model.addRow(rowData, entry.getDomain());

                // 确保新添加的行可见
                int lastRow = getRowCount() - 1;
                if (lastRow >= 0) {
                    scrollRectToVisible(getCellRect(lastRow, 0, true));
                }
            } catch (Exception e) {
                Utils.stderr.println("添加域名表格行失败: " + e.getMessage());
            }
        });
    }

    public void refreshEntry(DomainEntry entry) {
        if (entry == null || entry.getDomain() == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                String domain = entry.getDomain();
                for (int i = 0; i < model.getRowCount(); i++) {
                    if (domain.equals(model.getValueAt(i, 1))) {
                        model.setValueAt(entry.getId(), i, 0);
                        model.setValueAt(entry.getIp(), i, 2);
                        model.setValueAt(entry.getTimestamp(), i, 3);
                        break;
                    }
                }
            } catch (Exception e) {
                Utils.stderr.println("刷新域名表格行失败: " + e.getMessage());
            }
        });
    }

    public void clearData() {
        SwingUtilities.invokeLater(() -> {
            model.clearData();
        });
    }

    public void startBatchUpdate() {
        model.startBatchUpdate();
    }

    public void endBatchUpdate() {
        model.endBatchUpdate();
    }
}