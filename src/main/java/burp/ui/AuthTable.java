package burp.ui;

import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

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
        AuthEntry entry = AuthUI.getAuthlog().get(row);
        if (requestEditor != null) {
            requestEditor.setMessage(entry.requestResponse.getRequest(), true);
        }
        if (responseEditor != null) {
            if (entry.requestResponse.getResponse() == null) {
                responseEditor.setMessage(new byte[0], false);
            } else {
                responseEditor.setMessage(entry.requestResponse.getResponse(), false);
            }
        }
        AuthUI.setCurrentlyDisplayedItem(entry.requestResponse);
        super.changeSelection(row, col, toggle, extend);
    }
}
