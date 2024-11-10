package burp.ui.SimilarHelper.dialog;

import burp.ui.SimilarHelper.bean.Project;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class DomainConfigDialog extends JDialog {
    private DefaultListModel<String> listModel;
    private JList<String> domainList;
    private Project currentProject;

    public DomainConfigDialog(Window owner, Project project) {
        super(owner, "主域名配置", ModalityType.APPLICATION_MODAL);
        this.currentProject = project;
        initializeUI();
        loadDomains();
        setSize(400, 500);
        setLocationRelativeTo(owner);
    }

    private void initializeUI() {
        setLayout(new BorderLayout(5, 5));

        // 创建列表模型和列表
        listModel = new DefaultListModel<>();
        domainList = new JList<>(listModel);
        domainList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 添加滚动面板
        JScrollPane scrollPane = new JScrollPane(domainList);

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));

        JButton addButton = new JButton("添加域名");
        JButton editButton = new JButton("编辑域名");
        JButton deleteButton = new JButton("删除域名");
        JButton saveButton = new JButton("保存");

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(saveButton);

        // 添加组件到对话框
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(new JLabel("主域名列表:"), BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // 添加按钮事件
        addButton.addActionListener(e -> showAddDomainDialog());
        editButton.addActionListener(e -> showEditDomainDialog());
        deleteButton.addActionListener(e -> deleteDomain());
        saveButton.addActionListener(e -> {
            saveDomains();
            dispose();
        });
    }

    private void loadDomains() {
        listModel.clear();
        if (currentProject != null) {
            List<String> domains = currentProject.getMainDomains();
            domains.forEach(listModel::addElement);
        }
    }

    private void showAddDomainDialog() {
        String domain = JOptionPane.showInputDialog(this,
                "请输入域名:",
                "添加域名",
                JOptionPane.PLAIN_MESSAGE);

        if (domain != null && !domain.trim().isEmpty()) {
            domain = domain.trim().toLowerCase();
            if (!listModel.contains(domain)) {
                listModel.addElement(domain);
            } else {
                JOptionPane.showMessageDialog(this,
                        "域名已存在!",
                        "提示",
                        JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    private void showEditDomainDialog() {
        int selectedIndex = domainList.getSelectedIndex();
        if (selectedIndex != -1) {
            String oldDomain = listModel.getElementAt(selectedIndex);
            String newDomain = JOptionPane.showInputDialog(this,
                    "编辑域名:",
                    oldDomain);

            if (newDomain != null && !newDomain.trim().isEmpty()) {
                newDomain = newDomain.trim().toLowerCase();
                if (!listModel.contains(newDomain) || newDomain.equals(oldDomain)) {
                    listModel.setElementAt(newDomain, selectedIndex);
                } else {
                    JOptionPane.showMessageDialog(this,
                            "域名已存在!",
                            "提示",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(this,
                    "请先选择要编辑的域名!",
                    "提示",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void deleteDomain() {
        int selectedIndex = domainList.getSelectedIndex();
        if (selectedIndex != -1) {
            if (JOptionPane.showConfirmDialog(this,
                    "确定要删除选中的域名吗?",
                    "确认删除",
                    JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                listModel.remove(selectedIndex);
            }
        } else {
            JOptionPane.showMessageDialog(this,
                    "请先选择要删除的域名!",
                    "提示",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void saveDomains() {
        List<String> domains = new ArrayList<>();
        for (int i = 0; i < listModel.size(); i++) {
            domains.add(listModel.getElementAt(i));
        }
        currentProject.setMainDomains(domains);
    }
}
