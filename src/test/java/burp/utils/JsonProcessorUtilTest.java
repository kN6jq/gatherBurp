package burp.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class JsonProcessorUtilTest {

    @Test
    public void mutatesLeafValuesWithStablePathFormat() {
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath("{\"a\":{\"b\":\"x\"}}", "'", true);
        assertEquals(1, results.size());
        assertEquals("a.b", results.get(0).getParamPath());
        JSONObject parsed = JSON.parseObject(results.get(0).getModifiedJson());
        assertEquals("'", parsed.getJSONObject("a").getString("b"));
    }

    @Test
    public void handlesKeysContainingDots() {
        String body = "{\"user.name\":\"old\",\"nested\":{\"a.b\":\"v\"}}";
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath(body, "P", true);
        assertEquals(2, results.size());
        for (JsonProcessorUtil.ProcessResult result : results) {
            JSONObject parsed = JSON.parseObject(result.getModifiedJson());
            if ("user.name".equals(result.getParamPath())) {
                // "user.name" 是一个完整键：替换它不能被 '.' 切分后写进新建的 "user" 对象
                assertTrue(parsed.containsKey("user.name"));
                assertEquals("P", parsed.getString("user.name"));
                assertFalse(parsed.containsKey("user"));
            } else if ("nested.a.b".equals(result.getParamPath())) {
                assertEquals("P", parsed.getJSONObject("nested").getString("a.b"));
            } else {
                throw new AssertionError("unexpected path: " + result.getParamPath());
            }
        }
    }

    @Test
    public void recursesIntoNestedArrays() {
        String body = "{\"list\":[[\"x\",1],{\"k\":\"y\"}]}";
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath(body, "P", true);
        // 叶子：list[0][0]="x"、list[0][1]=1、list[1].k="y"
        assertEquals(3, results.size());
        boolean foundDeepArrayLeaf = false;
        for (JsonProcessorUtil.ProcessResult result : results) {
            if ("list[0][0]".equals(result.getParamPath())) {
                foundDeepArrayLeaf = true;
                JSONArray outer = JSON.parseObject(result.getModifiedJson()).getJSONArray("list");
                assertEquals("P", outer.getJSONArray(0).getString(0));
            }
        }
        assertTrue("嵌套数组叶子应被递归变异", foundDeepArrayLeaf);
    }

    @Test
    public void keepsPrimitiveLeavesValidJson() {
        String body = "{\"id\":5,\"flag\":true}";
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath(body, "-1", true);
        assertEquals(2, results.size());
        for (JsonProcessorUtil.ProcessResult result : results) {
            // 语法合法（parse 不抛异常），且数字叶子按原生数字类型替换
            assertNotNull(JSON.parse(result.getModifiedJson()));
            if ("id".equals(result.getParamPath())) {
                assertEquals(-1, JSON.parseObject(result.getModifiedJson()).getIntValue("id"));
            }
            if ("flag".equals(result.getParamPath())) {
                assertEquals("-1", JSON.parseObject(result.getModifiedJson()).getString("flag"));
            }
        }
    }

    @Test
    public void exposesOriginalLeafValueForTypeAwareProbing() {
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath("{\"id\":5,\"name\":\"abc\"}", "'", true);
        for (JsonProcessorUtil.ProcessResult result : results) {
            if ("id".equals(result.getParamPath())) {
                assertEquals("5", result.getOriginalValue());
            }
            if ("name".equals(result.getParamPath())) {
                assertEquals("abc", result.getOriginalValue());
            }
        }
    }

    @Test
    public void supportsTopLevelArrayRoot() {
        List<JsonProcessorUtil.ProcessResult> results =
                JsonProcessorUtil.processWithPath("[{\"k\":\"v\"}, \"s\"]", "P", true);
        assertEquals(2, results.size());
    }
}
