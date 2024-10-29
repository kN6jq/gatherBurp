package burp.ui.SimilarHelper;

import javax.swing.table.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.table.AbstractTableModel;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class OptimizedTableModel extends AbstractTableModel {
    private final List<List<Object>> data;
    private final String[] columnNames;
    private final Set<String> uniqueKeys;
    private boolean isUpdating = false;
    private final int keyColumnIndex;

    public OptimizedTableModel(String[] columnNames, int keyColumnIndex) {
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
        if (row < 0 || row >= data.size() || column < 0 || column >= columnNames.length) {
            return null;
        }
        List<Object> rowData = data.get(row);
        return column < rowData.size() ? rowData.get(column) : null;
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (row >= 0 && row < data.size() && column >= 0 && column < columnNames.length) {
            List<Object> rowData = data.get(row);
            if (column < rowData.size()) {
                rowData.set(column, value);
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

    public synchronized void addRow(List<Object> rowData, String uniqueKey) {
        if (!uniqueKeys.contains(uniqueKey)) {
            data.add(new ArrayList<>(rowData));
            uniqueKeys.add(uniqueKey);

            if (!isUpdating) {
                fireTableRowsInserted(data.size() - 1, data.size() - 1);
            }
        } else {
            // 如果已存在，更新现有行
            int row = findRowByKey(uniqueKey);
            if (row != -1) {
                data.set(row, new ArrayList<>(rowData));
                if (!isUpdating) {
                    fireTableRowsUpdated(row, row);
                }
            }
        }
    }

    private int findRowByKey(String key) {
        for (int i = 0; i < data.size(); i++) {
            List<Object> row = data.get(i);
            if (row.size() > keyColumnIndex && key.equals(row.get(keyColumnIndex).toString())) {
                return i;
            }
        }
        return -1;
    }

    public synchronized void startBatchUpdate() {
        isUpdating = true;
    }

    public synchronized void endBatchUpdate() {
        isUpdating = false;
        fireTableDataChanged();
    }

    public synchronized void clearData() {
        data.clear();
        uniqueKeys.clear();
        fireTableDataChanged();
    }

    public Set<String> getUniqueKeys() {
        return Collections.unmodifiableSet(uniqueKeys);
    }

    public boolean containsKey(String key) {
        return uniqueKeys.contains(key);
    }

    // 添加批量操作方法
    public synchronized void addRows(List<List<Object>> newRows, List<String> keys) {
        if (newRows.size() != keys.size()) {
            throw new IllegalArgumentException("行数据和键的数量不匹配");
        }

        startBatchUpdate();
        try {
            for (int i = 0; i < newRows.size(); i++) {
                addRow(newRows.get(i), keys.get(i));
            }
        } finally {
            endBatchUpdate();
        }
    }
}
