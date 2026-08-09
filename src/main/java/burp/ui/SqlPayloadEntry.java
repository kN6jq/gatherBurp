package burp.ui;

import burp.IHttpRequestResponse;

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
