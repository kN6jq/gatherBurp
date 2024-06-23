package burp.utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

/**
 * @Author Xm17
 * @Date 2024-06-23 9:57
 */
public class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return "";
    }

    @Override
    public String getRemediationBackground() {
        return "";
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return "";
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
