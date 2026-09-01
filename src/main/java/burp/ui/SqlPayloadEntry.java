package burp.ui;

import burp.IHttpRequestResponse;

/** SQL 模块 payload 探测结果表格条目：selectId 关联所属 URL 行；change 为相对基线的长度变化，
 *  time 为响应耗时（ms，字符串形式）。 */
public class SqlPayloadEntry {
    final int selectId;
    final String key;
    final String value;
    final int length;
    final String change;
    final String errkey;
    final String time;
    final String status;
    final IHttpRequestResponse requestResponse;

    public SqlPayloadEntry(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        this.selectId = selectId;
        this.key = key;
        this.value = value;
        this.length = length;
        this.change = change;
        this.errkey = errkey;
        this.time = time;
        this.status = status;
        this.requestResponse = requestResponse;
    }
}
