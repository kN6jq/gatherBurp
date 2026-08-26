package burp.ui;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.util.List;

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
        if (row < 0 || row >= getRowCount()) {
            return;
        }
        int modelRow = getRowSorter() == null ? row : convertRowIndexToModel(row);
        List<RouteIssueEntry> entries = RouteUI.getIssuslog();
        RouteIssueEntry entry;
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
        RouteUI.setCurrentlyDisplayedItem(message);
        super.changeSelection(row, col, toggle, extend);
    }
}
