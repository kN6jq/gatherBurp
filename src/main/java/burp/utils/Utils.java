package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import org.apache.commons.codec.net.URLCodec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;


public class Utils {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static String name = "gatherBurp";
    public static String version = "1.0.0";
    public static String author = "Xm17";
    public static String workdir = System.getProperty("user.home") + "/.gather/";

    public static String urlEncode(String input) {
        try {
            URLCodec codec = new URLCodec();
            return codec.encode(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return input; // 返回原始输入作为默认值
    }

    public static boolean isIP(String input) {
        String ipPattern = "^((\\d{1,3}\\.){3}\\d{1,3})$";
        return Pattern.matches(ipPattern, input);
    }

    public static List<String> getSuffix() {
        List<String> suffix = new ArrayList<>();
        suffix.add(".js");
        suffix.add(".css");
        suffix.add(".jpg");
        suffix.add(".png");
        suffix.add(".gif");
        suffix.add(".ico");
        suffix.add(".svg");
        suffix.add(".woff");
        suffix.add(".ttf");
        suffix.add(".eot");
        suffix.add(".woff2");
        suffix.add(".otf");
        suffix.add(".mp4");
        suffix.add(".mp3");
        suffix.add(".avi");
        suffix.add(".flv");
        suffix.add(".swf");
        suffix.add(".webp");
        suffix.add(".zip");
        suffix.add(".rar");
        suffix.add(".7z");
        suffix.add(".gz");
        suffix.add(".tar");
        suffix.add(".exe");
        suffix.add(".pdf");
        suffix.add(".doc");
        suffix.add(".docx");
        suffix.add(".xls");
        suffix.add(".xlsx");
        suffix.add(".ppt");
        suffix.add(".pptx");
        suffix.add(".txt");
        suffix.add(".xml");
        suffix.add(".apk");
        suffix.add(".ipa");
        suffix.add(".dmg");
        suffix.add(".iso");
        suffix.add(".img");
        suffix.add(".torrent");
        suffix.add(".jar");
        suffix.add(".war");
        suffix.add(".py");
        return suffix;
    }
    public static String RequestToFile(IHttpRequestResponse message) {
        try {
            String host = message.getHttpService().getHost();

            SimpleDateFormat simpleDateFormat =
                    new SimpleDateFormat("MMdd-HHmmss");
            String timeString = simpleDateFormat.format(new Date());
            String filename = host + "." + timeString + ".req";

            File requestFile = new File(workdir, filename);
            FileUtils.writeByteArrayToFile(requestFile, message.getRequest());
            return requestFile.getAbsolutePath();
        } catch (IOException e) {
            e.printStackTrace(stderr);
            return null;
        }
    }
    public static boolean isJSON(String test) {
        if (isJSONObject(test) || isJSONArray(test)) {
            return true;
        }else {
            return false;
        }
    }

    //org.json
    public static boolean isJSONObject(String test) {
        try {
            new JSONObject(test);
            return true;
        } catch (JSONException ex) {
            return false;
        }
    }


    public static boolean isJSONArray(String test) {
        try {
            new JSONArray(test);
            return true;
        } catch (JSONException ex) {
            return false;
        }
    }
    public static String updateJSONValue(String JSONString, String payload) throws Exception {

        if (isJSONObject(JSONString)) {
            JSONObject obj = new JSONObject(JSONString);
            Iterator<String> iterator = obj.keys();
            while (iterator.hasNext()) {
                String key = (String) iterator.next();		// We need to know keys of Jsonobject
                String value = obj.get(key).toString();


                if (isJSONObject(value)) {// if it's jsonobject
                    String newValue = updateJSONValue(value, payload);
                    obj.put(key,new JSONObject(newValue));
                }else if (isJSONArray(value)) {// if it's jsonarray
                    String newValue = updateJSONValue(value, payload);
                    obj.put(key,new JSONArray(newValue));
                }else {
                    if (!isBooleanOrNumber(value)){
                        obj.put(key, value+payload);
                    }
                }
            }
            return obj.toString();
        }else if(isJSONArray(JSONString)) {
            JSONArray jArray = new JSONArray(JSONString);

            ArrayList<String> newjArray = new ArrayList<String>();
            for (int i=0;i<jArray.length();i++) {//无论Array中的元素是JSONObject还是String都转换成String进行处理即可
                String item = jArray.get(i).toString();
                String newitem = updateJSONValue(item,payload);
                newjArray.add(newitem);
            }
            return newjArray.toString();
        }else {
            return JSONString+payload;
        }
    }

    public static boolean isBooleanOrNumber(String input) {
        if (input.toLowerCase().equals("true") || input.toLowerCase().equals("false")){
            return true;
        }else{
            return isNumeric(input);
        }
    }

    public static boolean isNumeric(String str){
        for(int i=str.length();--i>=0;){
            int chr=str.charAt(i);
            if(chr<48 || chr>57) {
                return false;
            }
        }
        return true;
    }




}
