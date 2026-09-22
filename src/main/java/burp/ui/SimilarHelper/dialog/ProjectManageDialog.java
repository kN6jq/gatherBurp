package burp.ui.SimilarHelper.dialog;

import burp.bean.SimilarProjectBean;
import burp.dao.SimilarProjectDao;
import burp.ui.SimilarHelper.ThreadManager;
import burp.ui.SimilarHelper.bean.Project;
import burp.utils.I18nUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** 项目选择/管理对话框（APPLICATION_MODAL，EDT 显示）：双击或"选择"按钮回调 onProjectSelected 并关闭；
 *  增/删项目直接写库并刷新列表。 */
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

    /** 选择当前选中项目：先 dispose 再回调（避免回调中访问已关闭组件）。 */
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
            // 建库放池线程（EDT 不等 SQLite 写锁），完成后回 EDT 刷新列表
            boolean accepted = ThreadManager.execute(() -> {
                try {
                    SimilarProjectDao.saveProject(new SimilarProjectBean(name));
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> showError(
                            I18nUtils.get("similar.dialog.create_project_failed") + e.getMessage()));
                    return;
                }
                SwingUtilities.invokeLater(this::refreshProjectList);
            });
            if (!accepted) {
                showError(I18nUtils.get("similar.dialog.create_project_failed") + "task rejected");
            }
        }
    }

    /** 确认后删除选中项目（删库在池线程，成功后回 EDT 同步列表）。 */
    private void deleteSelectedProject() {
        Project selected = projectList.getSelectedValue();
        if (selected != null) {
            int result = JOptionPane.showConfirmDialog(this,
                    I18nUtils.get("similar.dialog.confirm_delete_project") + selected.getName() + "' 吗？",
                    I18nUtils.get("similar.dialog.confirm_delete"),
                    JOptionPane.YES_NO_OPTION);

            if (result == JOptionPane.YES_OPTION) {
                boolean accepted = ThreadManager.execute(() -> {
                    try {
                        SimilarProjectDao.deleteProject(selected.getId());
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> showError(
                                I18nUtils.get("similar.dialog.delete_project_failed") + e.getMessage()));
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        projects.remove(selected);
                        listModel.removeElement(selected);
                    });
                });
                if (!accepted) {
                    showError(I18nUtils.get("similar.dialog.delete_project_failed") + "task rejected");
                }
            }
        }
    }

    /** 从库重新加载项目列表（查库在池线程，列表与 model 更新回 EDT）。 */
    private void refreshProjectList() {
        boolean accepted = ThreadManager.execute(() -> {
            List<Project> loaded = new ArrayList<>();
            AtomicReference<Exception> error = new AtomicReference<>();
            try {
                for (SimilarProjectBean bean : SimilarProjectDao.getAllProjects()) {
                    if (bean != null) {
                        loaded.add(new Project(bean));
                    }
                }
            } catch (Exception e) {
                error.set(e);
            }
            SwingUtilities.invokeLater(() -> {
                Exception loadError = error.get();
                if (loadError != null) {
                    showError(I18nUtils.get("similar.dialog.refresh_project_list_failed") + loadError.getMessage());
                    return;
                }
                listModel.clear();
                projects.clear();
                for (Project project : loaded) {
                    projects.add(project);
                    listModel.addElement(project);
                }
            });
        });
        if (!accepted) {
            showError(I18nUtils.get("similar.dialog.refresh_project_list_failed") + "task rejected");
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message,
                I18nUtils.get("similar.dialog.error"), JOptionPane.ERROR_MESSAGE);
    }
}