package burp.ui.SimilarHelper.dialog;

import burp.bean.SimilarProjectBean;
import burp.dao.SimilarProjectDao;
import burp.ui.SimilarHelper.bean.Project;
import burp.utils.I18nUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.function.Consumer;

public class ProjectManageDialog extends JDialog {
    private List<Project> projects;
    private JList<Project> projectList;
    private DefaultListModel<Project> listModel;
    private Consumer<Project> onProjectSelected;
    private boolean isProcessingSelection = false;  // 添加标志位防止重复处理

    public ProjectManageDialog(Window owner, List<Project> projects, Consumer<Project> onProjectSelected) {
        super(owner, I18nUtils.get("similar.dialog.project_manage_title"), ModalityType.APPLICATION_MODAL);
        this.projects = projects;
        this.onProjectSelected = onProjectSelected;

        initializeUI();
        setSize(400, 300);
        setLocationRelativeTo(owner);
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // 创建项目列表
        listModel = new DefaultListModel<>();
        projects.forEach(listModel::addElement);
        projectList = new JList<>(listModel);

        // 添加双击选择功能
        projectList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {  // 双击
                    selectProject();
                }
            }
        });

        // 按钮面板
        JPanel buttonPanel = new JPanel();
        JButton addButton = new JButton(I18nUtils.get("similar.dialog.add_project"));
        JButton deleteButton = new JButton(I18nUtils.get("similar.dialog.delete_project"));
        JButton selectButton = new JButton(I18nUtils.get("similar.dialog.select_project"));

        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(selectButton);

        add(new JScrollPane(projectList), BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // 添加事件监听
        addButton.addActionListener(e -> showAddProjectDialog());
        deleteButton.addActionListener(e -> deleteSelectedProject());
        selectButton.addActionListener(e -> selectProject());
    }

    private void selectProject() {
        if (isProcessingSelection) {
            return;  // 防止重复处理
        }

        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            isProcessingSelection = true;
            try {
                dispose();  // 先关闭对话框
                onProjectSelected.accept(selected);  // 再触发回调
            } finally {
                isProcessingSelection = false;
            }
        }
    }

    private void showAddProjectDialog() {
        String name = JOptionPane.showInputDialog(this, I18nUtils.get("similar.dialog.input_project_name"));
        if (name != null && !name.trim().isEmpty()) {
            try {
                // 创建项目Bean
                SimilarProjectBean projectBean = new SimilarProjectBean(name);
                // 保存到数据库
                SimilarProjectDao.saveProject(projectBean);
                // 重新加载项目列表
                refreshProjectList();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                        I18nUtils.get("similar.dialog.create_project_failed") + e.getMessage(),
                        I18nUtils.get("similar.dialog.error"),
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deleteSelectedProject() {
        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            int result = JOptionPane.showConfirmDialog(this,
                    I18nUtils.get("similar.dialog.confirm_delete_project") + selected.getName() + "' 吗？",
                    I18nUtils.get("similar.dialog.confirm_delete"),
                    JOptionPane.YES_NO_OPTION);

            if (result == JOptionPane.YES_OPTION) {
                try {
                    // 从数据库删除
                    SimilarProjectDao.deleteProject(selected.getId());
                    // 从列表中移除
                    projects.remove(selected);
                    listModel.removeElement(selected);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(this,
                            I18nUtils.get("similar.dialog.delete_project_failed") + e.getMessage(),
                            I18nUtils.get("similar.dialog.error"),
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void refreshProjectList() {
        try {
            // 清空列表
            listModel.clear();
            projects.clear();
            // 重新加载并转换类型
            List<SimilarProjectBean> projectBeans = SimilarProjectDao.getAllProjects();
            for (SimilarProjectBean bean : projectBeans) {
                Project project = new Project(bean);
                projects.add(project);
                listModel.addElement(project);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    I18nUtils.get("similar.dialog.refresh_project_list_failed") + e.getMessage(),
                    I18nUtils.get("similar.dialog.error"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}