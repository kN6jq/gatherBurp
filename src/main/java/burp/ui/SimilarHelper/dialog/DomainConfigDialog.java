package burp.ui.SimilarHelper.dialog;

import burp.ui.SimilarHelper.bean.Project;
import burp.utils.I18nUtils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class DomainConfigDialog extends JDialog {
    private DefaultListModel<String> listModel;
    private JList<String> domainList;
    private Project currentProject;

    public DomainConfigDialog(Window owner, Project project) {
        super(owner, I18nUtils.get("similar.dialog.domain_config_title"), ModalityType.APPLICATION_MODAL);
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

        JButton addButton = new JButton(I18nUtils.get("similar.dialog.add_domain"));
        JButton editButton = new JButton(I18nUtils.get("similar.dialog.edit_domain"));
        JButton deleteButton = new JButton(I18nUtils.get("similar.dialog.delete_domain"));
        JButton saveButton = new JButton(I18nUtils.get("similar.dialog.save"));

        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(saveButton);

        // 添加组件到对话框
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(new JLabel(I18nUtils.get("similar.dialog.domain_list")), BorderLayout.NORTH);
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
                I18nUtils.get("similar.dialog.input_domain"),
                I18nUtils.get("similar.dialog.add_domain_title"),
                JOptionPane.PLAIN_MESSAGE);

        if (domain != null && !domain.trim().isEmpty()) {
            domain = domain.trim().toLowerCase();
            if (!listModel.contains(domain)) {
                listModel.addElement(domain);
            } else {
                JOptionPane.showMessageDialog(this,
                        I18nUtils.get("similar.dialog.domain_exists"),
                        I18nUtils.get("similar.dialog.tip"),
                        JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    private void showEditDomainDialog() {
        int selectedIndex = domainList.getSelectedIndex();
        if (selectedIndex != -1) {
            String oldDomain = listModel.getElementAt(selectedIndex);
            String newDomain = JOptionPane.showInputDialog(this,
                    I18nUtils.get("similar.dialog.edit_domain"),
                    oldDomain);

            if (newDomain != null && !newDomain.trim().isEmpty()) {
                newDomain = newDomain.trim().toLowerCase();
                if (!listModel.contains(newDomain) || newDomain.equals(oldDomain)) {
                    listModel.setElementAt(newDomain, selectedIndex);
                } else {
                    JOptionPane.showMessageDialog(this,
                            I18nUtils.get("similar.dialog.domain_exists"),
                            I18nUtils.get("similar.dialog.tip"),
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(this,
                    I18nUtils.get("similar.dialog.select_domain_to_edit"),
                    I18nUtils.get("similar.dialog.tip"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void deleteDomain() {
        int selectedIndex = domainList.getSelectedIndex();
        if (selectedIndex != -1) {
            if (JOptionPane.showConfirmDialog(this,
                    I18nUtils.get("similar.dialog.confirm_delete_domain"),
                    I18nUtils.get("similar.dialog.confirm_delete"),
                    JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                listModel.remove(selectedIndex);
            }
        } else {
            JOptionPane.showMessageDialog(this,
                    I18nUtils.get("similar.dialog.select_domain_to_delete"),
                    I18nUtils.get("similar.dialog.tip"),
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
