package burp.utils;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.utils.Utils;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

public class SmartRequestDetector {

    private final IExtensionHelpers helpers;
    private final IHttpService httpService;
    private static final int[] BLOCKED_STATUS_CODES = {403,406,410};

    public SmartRequestDetector(IHttpService httpService) {
        this.helpers = Utils.helpers;
        this.httpService = httpService;
    }

    public IHttpRequestResponse smartSendRequest(String url, byte[] request) {
        IHttpRequestResponse normalResponse = sendRequest(url, request);
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

    private List<IHttpRequestResponse> tryEncodingBypass(String url, byte[] request) {
        List<IHttpRequestResponse> responses = new ArrayList<>();

        try {
            URL urlObj = new URL(url);
            String path = urlObj.getPath();
            String query = urlObj.getQuery();
            String fragment = urlObj.getRef();

            String[] encodedPaths = new String[] {
                path,
                urlEncodePath(path),
                doubleUrlEncodePath(path),
                unicodeEncodePath(path),
                mixedEncodePath(path)
            };

            for (String encodedPath : encodedPaths) {
                if (encodedPath == null || encodedPath.equals(path)) continue;

                String newUrl = buildUrl(urlObj, encodedPath, query, fragment);
                IHttpRequestResponse response = sendRequest(newUrl, request);
                if (response != null) {
                    responses.add(response);
                }
            }
        } catch (Exception e) {
        }

        return responses;
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

    private String buildUrl(URL urlObj, String path, String query, String fragment) {
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append(urlObj.getProtocol()).append("://");
        urlBuilder.append(urlObj.getHost());

        if (urlObj.getPort() != -1) {
            urlBuilder.append(":").append(urlObj.getPort());
        }

        urlBuilder.append(path);

        if (query != null && !query.isEmpty()) {
            urlBuilder.append("?").append(query);
        }

        if (fragment != null && !fragment.isEmpty()) {
            urlBuilder.append("#").append(fragment);
        }

        return urlBuilder.toString();
    }

    private IHttpRequestResponse sendRequest(String url, byte[] request) {
        try {
            byte[] newRequest = helpers.buildHttpRequest(new URL(url));
            return Utils.callbacks.makeHttpRequest(httpService, newRequest);
        } catch (MalformedURLException e) {
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