package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.table.AbstractTableModel;

public class RedirectModel extends AbstractTableModel {
    private final String[] COLUMNS = {"#", "Method", "URL", I18nUtils.get("redirect.label.parameter"), "Status Code", "Vulnerable"};

    @Override
    public int getRowCount() {
        return UrlRedirectUI.getRedirectLog().size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RedirectEntry entry = UrlRedirectUI.getRedirectLog().get(rowIndex);
        switch (columnIndex) {
            case 0: return entry.id;
            case 1: return entry.method;
            case 2: return entry.url;
            case 3: return entry.parameter;
            case 4: return entry.statusCode;
            case 5: return entry.isVulnerable ? I18nUtils.get("redirect.value.yes") : I18nUtils.get("redirect.value.no");
            default: return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) {
            return Integer.class;
        }
        return super.getColumnClass(column);
    }
}

