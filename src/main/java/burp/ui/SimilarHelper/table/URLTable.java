package burp.ui.SimilarHelper.table;

import burp.ui.SimilarHelper.tablemodel.TableModel;
import burp.ui.SimilarHelper.TableRenderer;
import burp.ui.SimilarHelper.bean.URL;
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
import java.util.stream.IntStream;

/**
 * URL表格组件
 * 用于展示和管理URL列表
 */
public class URLTable extends JTable {

    /**
     * 表格数据模型
     */
    private final TableModel model;

    /**
     * 右键菜单
     */
    private final JPopupMenu popupMenu;

    /**
     * 表格是否已销毁
     */
    private boolean disposed = false;

    /**
     * 构造函数
     */
    public URLTable() {
        // 初始化表格模型
        model = new TableModel(
                new String[]{"ID", "URL", "时间"},
                1  // URL列作为唯一键
        );
        setModel(model);

        // 初始化表格基本设置
        initializeTable();

        // 初始化右键菜单
        popupMenu = new JPopupMenu();
        setupContextMenu();

        // 设置快捷键
        setupKeyboardShortcuts();
    }

    /**
     * 初始化表格基本设置
     */
    private void initializeTable() {
        // 设置单元格渲染器
        setDefaultRenderer(Object.class, new TableRenderer());

        // 设置列宽
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(50);     // ID列
        columnModel.getColumn(1).setPreferredWidth(400);    // URL列
        columnModel.getColumn(2).setPreferredWidth(150);    // 时间列

        // 设置表格属性
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); // 允许多选
        setRowHeight(20);
        setAutoCreateRowSorter(true);
        setDoubleBuffered(true);
    }

    /**
     * 设置右键菜单
     */
    private void setupContextMenu() {
        // 复制选中URL菜单项
        JMenuItem copyUrlItem = new JMenuItem("复制选中URL");
        copyUrlItem.setMnemonic(KeyEvent.VK_C);
        copyUrlItem.addActionListener(e -> copySelectedUrls());

        // 复制全部URL菜单项
        JMenuItem copyAllItem = new JMenuItem("复制全部URL");
        copyAllItem.setMnemonic(KeyEvent.VK_A);
        copyAllItem.addActionListener(e -> copyAllUrls());

        // 清除选择菜单项
        JMenuItem clearSelectionItem = new JMenuItem("清除选择");
        clearSelectionItem.setMnemonic(KeyEvent.VK_L);
        clearSelectionItem.addActionListener(e -> clearSelection());

        // 添加菜单项
        popupMenu.add(copyUrlItem);
        popupMenu.add(copyAllItem);
        popupMenu.addSeparator();
        popupMenu.add(clearSelectionItem);

        // 添加鼠标监听器
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                handleContextMenu(e);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handleContextMenu(e);
            }
        });
    }

    /**
     * 处理右键菜单事件
     */
    private void handleContextMenu(MouseEvent e) {
        if (!disposed && e.isPopupTrigger()) {
            // 如果点击位置有行,且未被选中,则选中该行
            int row = rowAtPoint(e.getPoint());
            if (row >= 0 && !isRowSelected(row)) {
                setRowSelectionInterval(row, row);
            }

            // 表格有数据时显示菜单
            if (getRowCount() > 0) {
                popupMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        }
    }

    /**
     * 设置键盘快捷键
     */
    private void setupKeyboardShortcuts() {
        // 设置Ctrl+C复制快捷键
        KeyStroke copy = KeyStroke.getKeyStroke(KeyEvent.VK_C,
                Toolkit.getDefaultToolkit().getMenuShortcutKeyMask());
        registerKeyboardAction(e -> copySelectedUrls(),
                "Copy", copy, JComponent.WHEN_FOCUSED);

        // 设置Ctrl+A全选快捷键
        KeyStroke selectAll = KeyStroke.getKeyStroke(KeyEvent.VK_A,
                Toolkit.getDefaultToolkit().getMenuShortcutKeyMask());
        registerKeyboardAction(e -> selectAll(),
                "SelectAll", selectAll, JComponent.WHEN_FOCUSED);
    }

    /**
     * 复制选中的URL到剪贴板
     */
    private void copySelectedUrls() {
        if (disposed) return;

        int[] selectedRows = getSelectedRows();
        if (selectedRows.length > 0) {
            // 收集选中的URL并用换行符连接
            String urls = Arrays.stream(selectedRows)
                    .mapToObj(row -> getValueAt(row, 1).toString())
                    .collect(Collectors.joining("\n"));

            copyToClipboard(urls);
            Utils.stdout.println("已复制 " + selectedRows.length + " 个URL到剪贴板");
        }
    }

    /**
     * 复制所有URL到剪贴板
     */
    private void copyAllUrls() {
        if (disposed) return;

        if (getRowCount() > 0) {
            // 收集所有URL并用换行符连接
            String urls = IntStream.range(0, getRowCount())
                    .mapToObj(row -> getValueAt(row, 1).toString())
                    .collect(Collectors.joining("\n"));

            copyToClipboard(urls);
            Utils.stdout.println("已复制全部 " + getRowCount() + " 个URL到剪贴板");
        }
    }

    /**
     * 复制文本到剪贴板
     */
    private void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            try {
                StringSelection selection = new StringSelection(text);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, selection);
            } catch (Exception e) {
                Utils.stderr.println("复制到剪贴板失败: " + e.getMessage());
            }
        }
    }

    /**
     * 添加URL条目
     */
    public void addEntry(URL entry) {
        if (entry == null || entry.getUrl() == null || disposed) {
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

                // 滚动到新添加的行
                int lastRow = getRowCount() - 1;
                if (lastRow >= 0) {
                    scrollRectToVisible(getCellRect(lastRow, 0, true));
                }
            } catch (Exception e) {
                Utils.stderr.println("添加URL表格行失败: " + e.getMessage());
            }
        });
    }

    /**
     * 清空表格数据
     */
    public void clearData() {
        if (!disposed) {
            SwingUtilities.invokeLater(() -> model.clearData());
        }
    }

    /**
     * 开始批量更新
     */
    public void startBatchUpdate() {
        if (!disposed) {
            model.startBatchUpdate();
        }
    }

    /**
     * 结束批量更新
     */
    public void endBatchUpdate() {
        if (!disposed) {
            model.endBatchUpdate();
        }
    }
}