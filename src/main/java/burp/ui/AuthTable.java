package burp.ui;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.util.List;

public class AuthTable extends JTable {
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;

    public AuthTable(TableModel tableModel, IMessageEditor requestEditor, IMessageEditor responseEditor) {
        super(tableModel);
        this.requestEditor = requestEditor;
        this.responseEditor = responseEditor;
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(4).setMaxWidth(50);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        if (row < 0 || row >= getRowCount()) {
            return;
        }
        int modelRow = getRowSorter() == null ? row : convertRowIndexToModel(row);
        List<AuthEntry> entries = AuthUI.getAuthlog();
        AuthEntry entry;
        synchronized (entries) {
            if (modelRow < 0 || modelRow >= entries.size()) {
                return;
            }
            entry = entries.get(modelRow);
        }
        IHttpRequestResponse message = entry.requestResponse;
        if (message == null) {
            return;
        }
        if (requestEditor != null) {
            requestEditor.setMessage(message.getRequest(), true);
        }
        if (responseEditor != null) {
            responseEditor.setMessage(message.getResponse() == null ? new byte[0] : message.getResponse(), false);
        }
        AuthUI.setCurrentlyDisplayedItem(message);
        super.changeSelection(row, col, toggle, extend);
    }
}
