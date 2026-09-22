package burp.ui.SimilarHelper.dialog;

import burp.ui.SimilarHelper.bean.Project;
import burp.ui.SimilarHelper.ThreadManager;
import burp.utils.I18nUtils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/** 项目主域名配置对话框（APPLICATION_MODAL，EDT 显示）：增/改/删仅改本地列表，
 *  点"保存"才经 Project.setMainDomains 写库（全删全插）并关闭。域名统一 trim + 小写。 */
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
        saveButton.addActionListener(e -> saveDomains());
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

    /** 将当前列表整体保存到项目（写库全删全插，放池线程避免 EDT 卡 SQLite 写锁），完成后关闭对话框。 */
    private void saveDomains() {
        List<String> domains = new ArrayList<>();
        for (int i = 0; i < listModel.size(); i++) {
            domains.add(listModel.getElementAt(i));
        }
        boolean accepted = ThreadManager.execute(() -> {
            try {
                currentProject.replaceMainDomains(domains);
            } finally {
                SwingUtilities.invokeLater(this::dispose);
            }
        });
        if (!accepted) {
            // 任务被拒（池关闭/队列满）时直接关闭，不能让对话框卡死不消失
            dispose();
        }
    }
}
