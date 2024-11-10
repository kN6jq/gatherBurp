package burp.ui.SimilarHelper.tablemodel;

import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 优化的表格数据模型
 * 支持批量更新、唯一键约束和线程安全操作
 */
public class TableModel extends AbstractTableModel {
    // 存储表格数据的线程安全列表
    private final List<List<Object>> data;
    // 列名数组
    private final String[] columnNames;
    // 用于确保行的唯一性的键集合
    private final Set<String> uniqueKeys;
    // 用作唯一键的列索引
    private final int keyColumnIndex;
    // 批量更新标志
    private boolean isUpdating = false;

    /**
     * 构造函数
     *
     * @param columnNames    列名数组
     * @param keyColumnIndex 用作唯一键的列索引
     */
    public TableModel(String[] columnNames, int keyColumnIndex) {
        this.columnNames = columnNames;
        this.keyColumnIndex = keyColumnIndex;
        this.data = new CopyOnWriteArrayList<>();
        this.uniqueKeys = Collections.synchronizedSet(new HashSet<>());
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int row, int column) {
        // 边界检查
        if (row < 0 || row >= data.size() || column < 0 || column >= columnNames.length) {
            return null;
        }
        List<Object> rowData = data.get(row);
        return column < rowData.size() ? rowData.get(column) : null;
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        // 边界检查
        if (row >= 0 && row < data.size() && column >= 0 && column < columnNames.length) {
            List<Object> rowData = data.get(row);
            if (column < rowData.size()) {
                rowData.set(column, value);
                // 非批量更新模式下才触发单元格更新事件
                if (!isUpdating) {
                    fireTableCellUpdated(row, column);
                }
            }
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }

    /**
     * 添加新行或更新现有行
     * @param rowData 行数据
     * @param uniqueKey 唯一键值
     */
    public synchronized void addRow(List<Object> rowData, String uniqueKey) {
        if (!uniqueKeys.contains(uniqueKey)) {
            // 新行添加
            data.add(new ArrayList<>(rowData));
            uniqueKeys.add(uniqueKey);

            if (!isUpdating) {
                fireTableRowsInserted(data.size() - 1, data.size() - 1);
            }
        } else {
            // 更新现有行
            int row = findRowByKey(uniqueKey);
            if (row != -1) {
                data.set(row, new ArrayList<>(rowData));
                if (!isUpdating) {
                    fireTableRowsUpdated(row, row);
                }
            }
        }
    }

    /**
     * 根据唯一键查找行索引
     * @param key 唯一键值
     * @return 行索引，未找到返回-1
     */
    private int findRowByKey(String key) {
        for (int i = 0; i < data.size(); i++) {
            List<Object> row = data.get(i);
            if (row.size() > keyColumnIndex && key.equals(row.get(keyColumnIndex).toString())) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 开始批量更新，暂停表格刷新
     */
    public synchronized void startBatchUpdate() {
        isUpdating = true;
    }

    /**
     * 结束批量更新，触发表格刷新
     */
    public synchronized void endBatchUpdate() {
        isUpdating = false;
        fireTableDataChanged();
    }

    /**
     * 清空表格数据
     */
    public synchronized void clearData() {
        data.clear();
        uniqueKeys.clear();
        fireTableDataChanged();
    }

    /**
     * 清理表格模型资源
     * 在不再需要表格模型时调用此方法进行资源清理
     */
    public synchronized void cleanup() {
        // 清空所有数据
        clearData();

        // 重置更新标志
        isUpdating = false;
    }
}