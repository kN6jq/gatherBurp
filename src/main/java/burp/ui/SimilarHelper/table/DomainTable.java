package burp.ui.SimilarHelper.table;

import burp.ui.SimilarHelper.tablemodel.TableModel;
import burp.ui.SimilarHelper.TableRenderer;
import burp.ui.SimilarHelper.bean.Domain;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;

/**
 * 优化的域名表格组件
 */
public class DomainTable extends JTable {

    /**
     * 表格数据模型
     */
    private final TableModel model;

    /**
     * 表格是否已销毁
     */
    private boolean disposed = false;

    /**
     * 构造函数,初始化表格
     */
    public DomainTable() {
        // 初始化表格模型
        model = new TableModel(
                new String[]{"ID", "域名", "IP", "时间"},
                1  // 域名列作为唯一键
        );
        setModel(model);

        // 初始化表格设置
        initializeTable();

        // 设置右键菜单
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
        columnModel.getColumn(1).setPreferredWidth(200);    // 域名列
        columnModel.getColumn(2).setPreferredWidth(100);    // IP列
        columnModel.getColumn(3).setPreferredWidth(150);    // 时间列

        // 设置表格属性
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); // 允许多选
        setRowHeight(20);
        setAutoCreateRowSorter(true);
        setDoubleBuffered(true);
    }

    /**
     * 设置键盘快捷键
     */
    private void setupKeyboardShortcuts() {
        // 添加Ctrl+A全选快捷键
        this.getInputMap().put(
                KeyStroke.getKeyStroke(KeyEvent.VK_A, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()),
                "selectAll"
        );

        // 添加Ctrl+C复制快捷键
        this.getInputMap().put(
                KeyStroke.getKeyStroke(KeyEvent.VK_C, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask()),
                "copy"
        );

        // 设置复制动作
        this.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                copySelectedRows();
            }
        });
    }

    /**
     * 设置右键菜单
     */
    private void setupContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        // 复制域名菜单项
        JMenuItem copyDomainItem = new JMenuItem("复制域名");
        copyDomainItem.addActionListener(e -> copySelectedColumn(1));

        // 复制IP菜单项
        JMenuItem copyIPItem = new JMenuItem("复制IP");
        copyIPItem.addActionListener(e -> copySelectedColumn(2));

        // 复制全部选中内容菜单项
        JMenuItem copyAllSelectedItem = new JMenuItem("复制选中内容");
        copyAllSelectedItem.addActionListener(e -> copySelectedRows());

        // 添加菜单项
        popupMenu.add(copyDomainItem);
        popupMenu.add(copyIPItem);
        popupMenu.add(copyAllSelectedItem);

        // 添加鼠标右键监听
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger() && !disposed) {
                    int row = rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        // 如果点击的行未被选中,则选中该行
                        if (!isRowSelected(row)) {
                            setRowSelectionInterval(row, row);
                        }
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });
    }

    /**
     * 复制选中的列数据
     */
    private void copySelectedColumn(int column) {
        int[] rows = getSelectedRows();
        if (rows.length == 0) {
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rows.length; i++) {
            if (i > 0) {
                sb.append("\n");
            }
            Object value = getValueAt(rows[i], column);
            sb.append(value != null ? value.toString() : "");
        }

        copyToClipboard(sb.toString());
    }

    /**
     * 复制选中的所有行数据
     */
    private void copySelectedRows() {
        int[] rows = getSelectedRows();
        if (rows.length == 0) {
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int row : rows) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            for (int col = 0; col < getColumnCount(); col++) {
                if (col > 0) {
                    sb.append("\t");
                }
                Object value = getValueAt(row, col);
                sb.append(value != null ? value.toString() : "");
            }
        }

        copyToClipboard(sb.toString());
    }

    /**
     * 复制内容到剪贴板
     */
    private void copyToClipboard(String content) {
        if (content == null || content.isEmpty()) {
            return;
        }

        try {
            StringSelection selection = new StringSelection(content);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
        } catch (Exception e) {
            Utils.stderr.println("复制到剪贴板失败: " + e.getMessage());
        }
    }

    /**
     * 添加新的域名条目
     */
    public void addEntry(Domain entry) {
        if (entry == null || entry.getDomain() == null || disposed) {
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

                // 滚动到新添加的行
                int lastRow = getRowCount() - 1;
                if (lastRow >= 0) {
                    scrollRectToVisible(getCellRect(lastRow, 0, true));
                }
            } catch (Exception e) {
                Utils.stderr.println("添加域名表格行失败: " + e.getMessage());
            }
        });
    }

    /**
     * 刷新域名条目
     */
    public void refreshEntry(Domain entry) {
        if (entry == null || entry.getDomain() == null || disposed) {
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