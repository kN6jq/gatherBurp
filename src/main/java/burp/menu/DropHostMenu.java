package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.SqlUI;
import burp.utils.Utils;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;

public class DropHostMenu extends JMenuItem {
    public DropHostMenu() {
    }

    public DropHostMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ Drop Host");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new DropHostMenu().DropHost(responses);
                    }
                });
                thread.start();

            }
        });
    }

    private void DropHost(IHttpRequestResponse[] responses) {
        HashSet<String> hostHashSet = new HashSet<>();
        for(IHttpRequestResponse message:responses) {

            String host = message.getHttpService().getHost();
            host = dotToEscapeDot(host);
            hostHashSet.add(host);
        }

        AddHostToExScopeAdvByProjectConfig(hostHashSet);
    }

    public static void AddHostToExScopeAdvByProjectConfig( HashSet<String> hostHashSet) {
        if (hostHashSet.size() > 0) {
            // 读取当前的配置文件
            String configContent = Utils.callbacks.saveConfigAsJson();
            JSONObject jsonObject = new JSONObject(configContent);

            // 设置高级模式
            jsonObject.getJSONObject("target").getJSONObject("scope").put("advanced_mode", true);

            // 生成ExcludeJson元素并循环添加到json对象中
            JSONArray excludeJsonArray = jsonObject.getJSONObject("target").getJSONObject("scope").getJSONArray("exclude");
            for (String host : hostHashSet) {
                JSONObject excludeJsonObject = new JSONObject();
                excludeJsonObject.put("enabled", true);
                excludeJsonObject.put("host", host);
                excludeJsonObject.put("protocol", "any");
                excludeJsonArray.put(excludeJsonObject);
            }

            // 去重Json对象的排除列表
            JSONArray removeDuplicateJsonArray = DeDuplicateJsonObjectJsonArray(excludeJsonArray, "host");
            jsonObject.getJSONObject("target").getJSONObject("scope").put("exclude", removeDuplicateJsonArray);

            // 判断包含列表是否存在和排除列表相同的数据
            JSONArray includeJsonArray = jsonObject.getJSONObject("target").getJSONObject("scope").getJSONArray("include");
            if (includeJsonArray.length() > 0) {
                // 去除包含列表中和排除列表相同的数据
                JSONArray removeJsonObjectJsonArray = RemoveJsonObjectJsonArray(includeJsonArray, "host", hostHashSet);
                jsonObject.getJSONObject("target").getJSONObject("scope").put("include", removeJsonObjectJsonArray);
            }

            // 判断包含列表是否为空，如果include Scope为空需要修改为.*，否则全部删除
            includeJsonArray = jsonObject.getJSONObject("target").getJSONObject("scope").getJSONArray("include");
            if (includeJsonArray.length() < 1) {
                JSONObject includeJsonObject = new JSONObject();
                includeJsonObject.put("enabled", true);
                includeJsonObject.put("host", ".*");
                includeJsonObject.put("protocol", "any");
                includeJsonArray.put(includeJsonObject);
            }

            // 加载Json文件
            String jsonObjectString = jsonObject.toString();
            Utils.callbacks.loadConfigFromJson(jsonObjectString);

            // 根据用户设置，保存当前内存的配置到Json配置到文件
            autoSaveProjectConfig();
        }
    }
    public static JSONArray DeDuplicateJsonObjectJsonArray(JSONArray jsonArray, String jsonObjectKey) {
        HashSet<String> hashSet = new HashSet<>();
        JSONArray resultJsonArray = new JSONArray();

        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            String jsonElement = jsonObject.getString(jsonObjectKey);
            if (!hashSet.contains(jsonElement)) {
                resultJsonArray.put(jsonObject);
                hashSet.add(jsonElement);
            }
        }

        return resultJsonArray;
    }
    public static JSONArray RemoveJsonObjectJsonArray(JSONArray jsonArray, String jsonObjectKey, HashSet<String> hashSet) {
        JSONArray resultJsonArray = new JSONArray();
        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            String jsonElement = jsonObject.getString(jsonObjectKey);
            if (!hashSet.contains(jsonElement)) {
                resultJsonArray.put(jsonObject);
            }
        }
        return resultJsonArray;
    }
    public static void autoSaveProjectConfig(){
        String configPath = Utils.workdir+ "config.json";
        File file = new File(configPath);
        try{
            String configAsJson = Utils.callbacks.saveConfigAsJson();
            FileUtils.write(file, configAsJson, "UTF-8");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static String dotToEscapeDot(String host ) {
        return host.replace(".","\\.");
    }


}
