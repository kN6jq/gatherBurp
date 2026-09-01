package burp.ui;

import burp.ui.AuthEntry;

import javax.swing.table.AbstractTableModel;

/** 目录穿越结果表格模型：读 AuthUI 静态有界 store 的内部列表（以其为监视器加锁）；
 *  JTable 读取发生在 EDT。 */
public class AuthModel extends AbstractTableModel {
    @Override
    public int getRowCount() {
        synchronized (AuthUI.getAuthlog()) {
            return AuthUI.getAuthlog().size();
        }
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (AuthUI.getAuthlog()) {
            if (rowIndex < 0 || rowIndex >= AuthUI.getAuthlog().size()) {
                return null;
            }
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

