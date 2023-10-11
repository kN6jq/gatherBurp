package burp.ui;



import burp.IBurpExtenderCallbacks;
import burp.bean.Config;
import burp.utils.Utils;
import org.apache.commons.io.FileUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static burp.dao.ConfigDAO.*;
import static burp.dao.ConfigDAO.updateConfigSetting;


public class ConfigUI extends JPanel implements UIHandler{
    private static final List<ConfigUI.DataEntry> data = new ArrayList<>();
    public AbstractTableModel dataModel = new ConfigUI.MyModel();
    private JPanel panel1;
    private JLabel label2;
    private JTextField textField3;
    private JLabel label3;
    private JTextField textField4;
    private JLabel label4;
    private JTextField textField5;
    private JLabel label5;
    private JTextField textField6;
    private JPanel panel2;
    private JSplitPane splitPane1;
    private JPanel panel6;
    private JButton refershButton;
    private JButton saveDnsButton;
    private JButton saveIpButton;
    private JButton saveToolButton;
    private JButton deleteSelectButton;
    private JButton deleteHostButton;
    private JScrollPane scrollPane2;
    private JTable table1;

    @Override
    public void init() {

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        JPanel panel = new JPanel();

// JFormDesigner - Component initialization - DO NOT MODIFY
        panel1 = new JPanel();
        label2 = new JLabel();
        textField3 = new JTextField();
        label3 = new JLabel();
        textField4 = new JTextField();
        label4 = new JLabel();
        textField5 = new JTextField();
        label5 = new JLabel();
        textField6 = new JTextField();
        panel2 = new JPanel();
        splitPane1 = new JSplitPane();
        panel6 = new JPanel();
        refershButton = new JButton();
        saveDnsButton = new JButton();
        saveIpButton = new JButton();
        saveToolButton = new JButton();
        deleteSelectButton = new JButton();
        deleteHostButton = new JButton();
        table1 = new JTable(dataModel);
        scrollPane2 = new JScrollPane(table1);

//======== this ========
        setLayout(new BorderLayout());

//======== splitPane ========
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(150); // Set the initial divider location

//======== panel1 ========
        panel1.setLayout(new GridLayout(0, 2, 5, 5)); // Single column layout with gaps

//---- label2 ----
        label2.setText("dnslog");
        panel1.add(label2);

//---- textField3 ----
        textField3.setText("www.dnslog.cn");
        textField3.setColumns(20);
        panel1.add(textField3);

//---- label3 ----
        label3.setText("ip");
        panel1.add(label3);

//---- textField4 ----
        textField4.setText("127.0.0.1");
        textField4.setColumns(20);
        panel1.add(textField4);

//---- label4 ----
        label4.setText("工具配置");
        panel1.add(label4);

//---- textField5 ----
        textField5.setText("sqlmap");
        textField5.setColumns(20);
        panel1.add(textField5);

//---- label5 ----
        label5.setText("工具参数");
        panel1.add(label5);

//---- textField6 ----
        textField6.setText("c:\\sqlmap\\sqlmap.py -r 1.txt --batch --tamper=space2comment");
        textField6.setColumns(20);
        panel1.add(textField6);

        splitPane.setTopComponent(panel1);

//======== panel2 ========
        panel2.setLayout(new BorderLayout());

//======== splitPane1 ========
        splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);

//======== panel6 ========
        panel6.setLayout(new BoxLayout(panel6, BoxLayout.X_AXIS));

//---- refershButton ----
        refershButton.setText("刷新数据");
        panel6.add(refershButton);

//---- saveDnsButton ----
        saveDnsButton.setText("保存dns");
        panel6.add(saveDnsButton);

//---- saveIpButton ----
        saveIpButton.setText("保存ip");
        panel6.add(saveIpButton);

//---- saveToolButton ----
        saveToolButton.setText("保存工具配置");
        panel6.add(saveToolButton);

//---- deleteSelectButton ----
        deleteSelectButton.setText("删除选中");
        panel6.add(deleteSelectButton);

        deleteHostButton.setText("删除host过滤");
        panel6.add(deleteHostButton);

        splitPane1.setTopComponent(panel6);

//======== scrollPane2 ========
        scrollPane2.setViewportView(table1);
        splitPane1.setBottomComponent(scrollPane2);

        panel2.add(splitPane1, BorderLayout.CENTER);
        splitPane.setBottomComponent(panel2);

        add(splitPane, BorderLayout.CENTER);
        panel.add(splitPane);

        Config dnsSetting = getValueByModuleAndType("config", "dnslog");
        textField3.setText(dnsSetting.getValue());

        Config ipsetting = getValueByModuleAndType("config", "ip");
        textField4.setText(ipsetting.getValue());

        List<Config> toolParam = getToolConfig();
        for (Config config : toolParam) {
            addData(config.getType(), config.getValue());
        }
        refershButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<Config> toolParam = getToolConfig();
                data.clear();
                for (Config config : toolParam) {
                    addData(config.getType(), config.getValue());
                }
                dataModel.fireTableDataChanged();
            }
        });
        saveDnsButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String module = "config";
                String dns = textField3.getText();
                Config config = new Config(module,"dnslog", dns);
                updateConfigSetting(config);
            }
        });

        saveIpButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String module = "config";
                String ip = textField4.getText();
                Config config = new Config(module,"ip", ip);
                updateConfigSetting(config);
            }
        });
        saveToolButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String module = "tool";
                String tool = textField5.getText();
                String param = textField6.getText();
                Config config = new Config(module,tool, param);
                saveConfigSetting(config);
            }
        });
        deleteSelectButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table1.getSelectedRows();
                for (int i = selectedRows.length - 1; i >= 0; i--) {
                    int selectedRow = selectedRows[i];
                    String type = (String) table1.getValueAt(selectedRow, 1);
                    Config config = new Config(type, "");
                    deleteConfig(config);
                    data.remove(selectedRow);
                    dataModel.fireTableRowsDeleted(selectedRow, selectedRow);
                    dataModel.fireTableDataChanged();
                }
            }
        });
        deleteHostButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String configPath = Utils.workdir+ "config.json";
                File file = new File(configPath);
                try {
                    FileUtils.delete(file);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });
        return panel;


    }

    public void addData(String key, String value) {
        synchronized (data) {
            data.add(new DataEntry(data.size() + 1, key, value));
            dataModel.fireTableDataChanged();
            dataModel.fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }
    }

    @Override
    public String getTabName() {
        return "config";
    }

    class MyModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DataEntry dataEntry = data.get(rowIndex);
            switch (columnIndex){
                case 0:
                    return dataEntry.id;
                case 1:
                    return dataEntry.key;
                case 2:
                    return dataEntry.value;
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0:
                    return "id";
                case 1:
                    return "key";
                case 2:
                    return "value";
                default:
                    return null;
            }
        }
    }

    public class DataEntry{
        private int id;
        private String key;
        private String value;

        public DataEntry(int id, String key, String value) {
            this.id = id;
            this.key = key;
            this.value = value;
        }

        public DataEntry(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }
}
