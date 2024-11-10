package burp.ui.SimilarHelper.dialog;

import burp.bean.SimilarProjectBean;
import burp.dao.SimilarProjectDao;
import burp.ui.SimilarHelper.bean.Project;

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
        super(owner, "项目管理", ModalityType.APPLICATION_MODAL);
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
        JButton addButton = new JButton("新增项目");
        JButton deleteButton = new JButton("删除项目");
        JButton selectButton = new JButton("选择项目");

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
        String name = JOptionPane.showInputDialog(this, "请输入项目名称:");
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
                        "创建项目失败: " + e.getMessage(),
                        "错误",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void deleteSelectedProject() {
        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            int result = JOptionPane.showConfirmDialog(this,
                    "确定要删除项目 '" + selected.getName() + "' 吗？",
                    "确认删除",
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
                            "删除项目失败: " + e.getMessage(),
                            "错误",
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
                    "刷新项目列表失败: " + e.getMessage(),
                    "错误",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}