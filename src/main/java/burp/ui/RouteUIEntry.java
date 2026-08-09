package burp.ui;


public class RouteUIEntry {
    final int id;
    int enable;
    final String name;
    final String path;
    final String express;

    public RouteUIEntry(int id, int enable, String name, String path, String express) {
        this.id = id;
        this.enable = enable;
        this.name = name;
        this.path = path;
        this.express = express;
    }
}

