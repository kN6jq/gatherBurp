package burp.ui;

import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

public class FastjsonTable extends JTable {
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;

    public FastjsonTable(TableModel tableModel, IMessageEditor requestEditor, IMessageEditor responseEditor) {
        super(tableModel);
        this.requestEditor = requestEditor;
        this.responseEditor = responseEditor;
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(5).setMaxWidth(250);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        FastjsonEntry logEntry = FastjsonUI.getFastjsonlog().get(row);
        requestEditor.setMessage(logEntry.requestResponse.getRequest(), true);
        if (logEntry.requestResponse.getResponse() == null) {
            responseEditor.setMessage(new byte[0], false);
        } else {
            responseEditor.setMessage(logEntry.requestResponse.getResponse(), false);
        }
        FastjsonUI.setCurrentlyDisplayedItem(logEntry.requestResponse);
        super.changeSelection(row, col, toggle, extend);
    }
}
