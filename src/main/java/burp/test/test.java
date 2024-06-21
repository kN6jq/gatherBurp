package burp.test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

/**
 * @Author Xm17
 * @Date 2024-06-21 9:25
 */
// todo 此类json的解析
public class test {
    public static void main(String[] args) {
        String json = "[\"asd\"]";
        Object parse = JSON.parse(json);
        System.out.println(parse);
    }
}
