package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class SqlPayloadModel extends AbstractTableModel {
    private final List<SqlPayloadEntry> data;

    public SqlPayloadModel(List<SqlPayloadEntry> data) {
        this.data = data;
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SqlPayloadEntry entry = data.get(rowIndex);
        switch (columnIndex) {
            case 0: return entry.key;
            case 1: return entry.value;
            case 2: return entry.length;
            case 3: return entry.change;
            case 4: return entry.errkey;
            case 5: return entry.time;
            case 6: return entry.status;
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "Parameter";
            case 1: return "Value";
            case 2: return "Response Length";
            case 3: return "Change";
            case 4: return "Error";
            case 5: return "Time";
            case 6: return "Status Code";
            default: return null;
        }
    }
}
