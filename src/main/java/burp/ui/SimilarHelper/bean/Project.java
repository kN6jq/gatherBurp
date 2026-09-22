package burp.ui.SimilarHelper.bean;

import burp.bean.SimilarProjectBean;
import burp.dao.SimilarDomainConfigDao;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Similar 模块项目（内存聚合对象）：持有主域名清单。
 *  mainDomains 为 volatile 不可变快照——写方整体替换引用，池线程/EDT 只读遍历，
 *  避免一边换列表一边读。setMainDomains 只改内存（切项目加载/定时同步用），
 *  需要落库时（配置对话框保存）必须走 replaceMainDomains。 */
public class Project {
    private final int id;
    private String name;
    private String createTime;
    private volatile List<String> mainDomains = Collections.emptyList();

    public Project(SimilarProjectBean bean) {
        this.id = bean.getId();
        this.name = bean.getName();
        this.createTime = bean.getCreateTime();
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<String> getMainDomains() {
        return mainDomains;
    }

    /** 只更新内存中的主域名清单，不写库。加载/同步路径用这个：
     *  读库失败时顶多拿到空列表，不会把用户已存的配置删掉。 */
    public void setMainDomains(List<String> domains) {
        this.mainDomains = Collections.unmodifiableList(new ArrayList<>(domains));
    }

    /** 更新内存并整体写库（全删全插）。只在配置对话框"保存"时调用。 */
    public void replaceMainDomains(List<String> domains) {
        setMainDomains(domains);
        SimilarDomainConfigDao.saveDomainConfigs(id, domains);
    }

    @Override
    public String toString() {
        return name;
    }
}
