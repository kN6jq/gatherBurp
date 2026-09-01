package burp.utils;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.utils.Utils;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/** 智能请求发送器：发送原始请求并检测 WAF 拦截/编码绕过等信号（供 Route/SQL 探测复用）。 */
public class SmartRequestDetector {

    private final IExtensionHelpers helpers;
    private final IHttpService httpService;
    /** 拦截判定统一引用共享常量（403/406/410/429），与 Route 模块 WAF 信号口径一致。 */
    private static final int[] BLOCKED_STATUS_CODES = WafEvidence.BLOCKED_STATUS_CODES;

    public SmartRequestDetector(IHttpService httpService) {
        this.helpers = Utils.helpers;
        this.httpService = httpService;
    }

    /** 发送原始请求；成功直接返回，被拦截则尝试编码绕过变体，返回首个成功响应或原响应。 */
    public IHttpRequestResponse smartSendRequest(String url, byte[] request) {
        // 必须发送调用方构建的原始请求字节：其中携带原始 Cookie/Authorization/自定义头与 body。
        // 旧实现用 buildHttpRequest(new URL(url)) 从 URL 重建请求，导致原始头全部丢失，
        // 探测实际以未认证裸请求发出，绕过判定与证据请求均不可信。
        IHttpRequestResponse normalResponse = sendRequest(request);
        if (isSuccessResponse(normalResponse)) {
            return normalResponse;
        }

        if (isBlockedResponse(normalResponse)) {
            List<IHttpRequestResponse> encodedResponses = tryEncodingBypass(url, request);
            for (IHttpRequestResponse response : encodedResponses) {
                if (isSuccessResponse(response)) {
                    return response;
                }
            }
        }

        return normalResponse;
    }

    /** 生成编码绕过变体请求（单/双重 URL 编码、Unicode、混合编码）并发送，返回全部变体响应。 */
    private List<IHttpRequestResponse> tryEncodingBypass(String url, byte[] request) {
        List<IHttpRequestResponse> responses = new ArrayList<>();

        try {
            URL urlObj = new URL(url);
            String path = urlObj.getPath();
            String query = urlObj.getQuery();

            String[] encodedPaths = new String[] {
                urlEncodePath(path),
                doubleUrlEncodePath(path),
                unicodeEncodePath(path),
                mixedEncodePath(path)
            };

            for (String encodedPath : encodedPaths) {
                if (encodedPath == null || encodedPath.equals(path)) continue;

                String newTarget = (query != null && !query.isEmpty())
                        ? encodedPath + "?" + query : encodedPath;
                byte[] variantRequest = buildRequestWithTarget(request, newTarget);
                if (variantRequest == null) continue;
                IHttpRequestResponse response = sendRequest(variantRequest);
                if (response != null) {
                    responses.add(response);
                }
            }
        } catch (Exception ignored) {
        }

        return responses;
    }

    /**
     * 只替换请求行中的 request-target，保留原请求全部头与 body（认证态、Content-Length 不变）。
     * 用于编码绕过变体：变体请求与原始请求必须处于同一会话上下文，否则 403 归因失真。
     */
    static byte[] buildRequestWithTarget(byte[] request, String newTarget) {
        if (request == null || request.length == 0 || newTarget == null || newTarget.isEmpty()) {
            return null;
        }
        int lineEnd = -1;
        for (int i = 0; i + 1 < request.length; i++) {
            if (request[i] == '\r' && request[i + 1] == '\n') {
                lineEnd = i;
                break;
            }
        }
        if (lineEnd < 0) {
            return null;
        }
        String line = new String(request, 0, lineEnd, java.nio.charset.StandardCharsets.ISO_8859_1);
        int firstSpace = line.indexOf(' ');
        int lastSpace = line.lastIndexOf(' ');
        if (firstSpace < 0 || lastSpace <= firstSpace) {
            return null;
        }
        String newLine = line.substring(0, firstSpace + 1) + newTarget + line.substring(lastSpace);
        byte[] newLineBytes = newLine.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] result = new byte[newLineBytes.length + (request.length - lineEnd)];
        System.arraycopy(newLineBytes, 0, result, 0, newLineBytes.length);
        System.arraycopy(request, lineEnd, result, newLineBytes.length, request.length - lineEnd);
        return result;
    }

    private String urlEncodePath(String path) {
        try {
            String encoded = URLEncoder.encode(path, "UTF-8");
            return encoded.replace("%2F", "/")
                      .replace("%3D", "=")
                      .replace("%3F", "?")
                      .replace("%40", "@")
                      .replace("%3A", ":")
                      .replace("%26", "&")
                      .replace("%23", "#");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    private String doubleUrlEncodePath(String path) {
        try {
            String firstEncode = URLEncoder.encode(path, "UTF-8");
            String secondEncode = URLEncoder.encode(firstEncode, "UTF-8");
            return secondEncode.replace("%252F", "/")
                          .replace("%253D", "=")
                          .replace("%253F", "?")
                          .replace("%2540", "@")
                          .replace("%253A", ":");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    private String unicodeEncodePath(String path) {
        try {
            byte[] bytes = path.getBytes("UTF-8");
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) {
                if (b == '/') {
                    result.append('/');
                } else {
                    result.append(String.format("%%%02X", b & 0xFF));
                }
            }
            return result.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String mixedEncodePath(String path) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '/') {
                result.append(c);
            } else if (i % 2 == 0) {
                try {
                    result.append(URLEncoder.encode(String.valueOf(c), "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    result.append(c);
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private IHttpRequestResponse sendRequest(byte[] request) {
        try {
            return Utils.callbacks.makeHttpRequest(httpService, request);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isSuccessResponse(IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return false;
        }

        int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
        return statusCode >= 200 && statusCode < 300;
    }

    private boolean isBlockedResponse(IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return false;
        }

        int statusCode = helpers.analyzeResponse(response.getResponse()).getStatusCode();
        for (int blockedCode : BLOCKED_STATUS_CODES) {
            if (statusCode == blockedCode) {
                return true;
            }
        }
        return false;
    }
}