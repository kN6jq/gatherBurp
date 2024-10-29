package burp.ui.SimilarHelper;

import burp.bean.SimilarProjectBean;
import burp.dao.SimilarProjectDao;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

public class ProjectManageDialog extends JDialog {
    private List<Project> projects;
    private JList<Project> projectList;
    private DefaultListModel<Project> listModel;
    private Consumer<Project> onProjectSelected;

    public ProjectManageDialog(Window owner, List<Project> projects,
                               Consumer<Project> onProjectSelected) {
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

    private void showAddProjectDialog() {
        String name = JOptionPane.showInputDialog(this, "请输入项目名称:");
        if (name != null && !name.trim().isEmpty()) {
            // 创建项目Bean
            SimilarProjectBean projectBean = new SimilarProjectBean(name);
            // 保存到数据库
            SimilarProjectDao.saveProject(projectBean);
            // 重新加载项目列表
            refreshProjectList();
        }
    }

    private void deleteSelectedProject() {
        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            // 从数据库删除
            SimilarProjectDao.deleteProject(selected.getId());
            // 从列表中移除
            projects.remove(selected);
            listModel.removeElement(selected);
        }
    }

    private void refreshProjectList() {
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
    }

    private void selectProject() {
        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            onProjectSelected.accept(selected);
            dispose();
        }
    }
}
