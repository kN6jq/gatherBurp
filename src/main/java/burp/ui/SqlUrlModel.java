package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class SqlUrlModel extends AbstractTableModel {
    private final List<SqlUIEntry> data;

    public SqlUrlModel(List<SqlUIEntry> data) {
        this.data = data;
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SqlUIEntry entry = data.get(rowIndex);
        switch (columnIndex) {
            case 0: return entry.id;
            case 1: return entry.method;
            case 2: return entry.url;
            case 3: return entry.length;
            case 4: return entry.status;
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "id";
            case 1: return "method";
            case 2: return "url";
            case 3: return "length";
            case 4: return "status";
            default: return null;
        }
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) return Integer.class;
        return super.getColumnClass(column);
    }
}
