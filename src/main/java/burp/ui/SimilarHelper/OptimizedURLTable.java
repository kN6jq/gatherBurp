package burp.ui.SimilarHelper;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class OptimizedURLTable extends JTable {
    private final OptimizedTableModel model;

    public OptimizedURLTable() {
        model = new OptimizedTableModel(
                new String[]{"ID", "URL", "时间"},
                1  // URL列作为唯一键
        );
        setModel(model);

        // 设置渲染器
        setDefaultRenderer(Object.class, new OptimizedTableRenderer());

        // 设置列宽
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(50);
        columnModel.getColumn(1).setPreferredWidth(400);
        columnModel.getColumn(2).setPreferredWidth(150);

        // 优化表格属性
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); // 允许多选
        setRowHeight(20);

        // 开启表格排序
        setAutoCreateRowSorter(true);

        // 双缓冲提高渲染性能
        setDoubleBuffered(true);

        // 添加右键菜单
        setupContextMenu();

        // 添加快捷键
        setupKeyboardShortcuts();
    }

    private void setupContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        // 复制选中URL菜单项
        JMenuItem copyUrlItem = new JMenuItem("复制选中URL");
        copyUrlItem.addActionListener(e -> copySelectedUrls());

        popupMenu.add(copyUrlItem);

        // 添加鼠标监听
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }

            private void showContextMenu(MouseEvent e) {
                // 确保在有选中行时才显示菜单
                if (getSelectedRowCount() > 0 || getRowCount() > 0) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    private void setupKeyboardShortcuts() {
        // 添加Ctrl+C快捷键
        KeyStroke copy = KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask());
        registerKeyboardAction(e -> copySelectedUrls(), "Copy", copy, JComponent.WHEN_FOCUSED);
    }

    private void copySelectedUrls() {
        int[] selectedRows = getSelectedRows();
        if (selectedRows.length > 0) {
            String urls = Arrays.stream(selectedRows)
                    .mapToObj(row -> getValueAt(row, 1).toString()) // 1是URL列的索引
                    .collect(Collectors.joining("\n"));
            copyToClipboard(urls);

            // 可选：显示提示
            int count = selectedRows.length;
            Utils.stdout.println("已复制 " + count + " 个URL到剪贴板");
        }
    }



    private void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            StringSelection selection = new StringSelection(text);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
        }
    }

    public void addEntry(URLEntry entry) {
        if (entry == null || entry.getUrl() == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            try {
                List<Object> rowData = Arrays.asList(
                        entry.getId(),
                        entry.getUrl(),
                        entry.getTimestamp()
                );
                model.addRow(rowData, entry.getUrl());

                // 确保新添加的行可见
                int lastRow = getRowCount() - 1;
                if (lastRow >= 0) {
                    scrollRectToVisible(getCellRect(lastRow, 0, true));
                }
            } catch (Exception e) {
                Utils.stderr.println("添加URL表格行失败: " + e.getMessage());
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