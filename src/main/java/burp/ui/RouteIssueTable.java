package burp.ui;

import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

public class RouteIssueTable extends JTable {
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;

    public RouteIssueTable(TableModel tableModel, IMessageEditor requestEditor, IMessageEditor responseEditor) {
        super(tableModel);
        this.requestEditor = requestEditor;
        this.responseEditor = responseEditor;
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(1).setMinWidth(100);
        columnModel.getColumn(1).setMaxWidth(150);
        columnModel.getColumn(3).setMaxWidth(50);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        RouteIssueEntry issusEntry = RouteUI.getIssuslog().get(row);
        requestEditor.setMessage(issusEntry.requestResponse.getRequest(), true);
        if (issusEntry.requestResponse.getResponse() == null) {
            responseEditor.setMessage(new byte[0], false);
        } else {
            responseEditor.setMessage(issusEntry.requestResponse.getResponse(), false);
        }
        RouteUI.setCurrentlyDisplayedItem(issusEntry.requestResponse);
        super.changeSelection(row, col, toggle, extend);
    }
}

