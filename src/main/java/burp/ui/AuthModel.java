package burp.ui;

import burp.ui.AuthEntry;

import javax.swing.table.AbstractTableModel;

public class AuthModel extends AbstractTableModel {
    @Override
    public int getRowCount() {
        return AuthUI.getAuthlog().size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AuthEntry entry = AuthUI.getAuthlog().get(rowIndex);
        switch (columnIndex) {
            case 0: return entry.id;
            case 1: return entry.method;
            case 2: return entry.url;
            case 3: return entry.status;
            case 4: return entry.length;
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "id";
            case 1: return "method";
            case 2: return "url";
            case 3: return "status";
            case 4: return "length";
            default: return null;
        }
    }
}

