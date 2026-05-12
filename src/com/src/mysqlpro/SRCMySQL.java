package com.src.mysqlpro;

import android.os.AsyncTask;
import com.google.appinventor.components.annotations.*;
import com.google.appinventor.components.common.*;
import com.google.appinventor.components.runtime.*;
import com.google.appinventor.components.runtime.util.YailList;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * SRC MySQL Pro Extension v2.0
 * Shree Ram Computers - Daurala, Meerut, UP
 *
 * BETTER than Deep Host MySQL Extension:
 *  ✅ HMAC Signature Auth (no plain API key exposure)
 *  ✅ Session Token System (1 hour validity)
 *  ✅ Timestamp validation (replay attack protection)
 *  ✅ Full CRUD + Pagination + Aggregate + Like Search
 *  ✅ Custom SELECT query support
 *  ✅ JSON helper functions
 *  ✅ Rate limiting on server side
 */
@DesignerComponent(
    version = 2,
    description = "SRC MySQL Pro - Secure MySQL Extension by Shree Ram Computers, Daurala. Better than Deep Host: HMAC Auth, Session Token, Pagination, Aggregates.",
    category = ComponentCategory.EXTENSION,
    nonVisible = true,
    iconName = "aiwebres/icon.png"
)
@SimpleObject(external = true)
public class SRCMySQL extends AndroidNonvisibleComponent {

    private String serverUrl   = "";
    private String secretKey   = "";
    private String deviceToken = "";
    private boolean debugMode  = false;
    private int connectTimeout = 15000;
    private int readTimeout    = 30000;

    public SRCMySQL(ComponentContainer container) {
        super(container.$form());
    }

    // ==================== PROPERTIES ====================

    @DesignerProperty(defaultValue = "")
    @SimpleProperty(description = "Your SRC MySQL API server URL (e.g. https://yoursite.com/api/)")
    public void ServerUrl(String url) {
        this.serverUrl = url.endsWith("/") ? url : url + "/";
    }

    @DesignerProperty(defaultValue = "")
    @SimpleProperty(description = "Your Secret Key (same as in config.php on server). Never share this.")
    public void SecretKey(String key) {
        this.secretKey = key;
    }

    @DesignerProperty(defaultValue = "false", editorType = PropertyTypeConstants.PROPERTY_TYPE_BOOLEAN)
    @SimpleProperty(description = "Enable debug mode to get detailed errors.")
    public void DebugMode(boolean debug) {
        this.debugMode = debug;
    }

    @DesignerProperty(defaultValue = "15")
    @SimpleProperty(description = "Connection timeout in seconds (default: 15).")
    public void ConnectTimeoutSeconds(int seconds) {
        this.connectTimeout = seconds * 1000;
    }

    // ==================== EVENTS ====================

    @SimpleEvent(description = "Fired when any request succeeds. callId = request identifier, data = JSON result string.")
    public void OnSuccess(String callId, String data, int rowCount) {
        EventDispatcher.dispatchEvent(this, "OnSuccess", callId, data, rowCount);
    }

    @SimpleEvent(description = "Fired when any request fails. callId = request identifier, error = error message.")
    public void OnError(String callId, String error) {
        EventDispatcher.dispatchEvent(this, "OnError", callId, error);
    }

    @SimpleEvent(description = "Fired when Authenticate() succeeds. Save this token if needed.")
    public void OnAuthenticated(String sessionToken, int expiresInSeconds) {
        EventDispatcher.dispatchEvent(this, "OnAuthenticated", sessionToken, expiresInSeconds);
    }

    // ==================== HMAC SIGNATURE ====================

    private String hmac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // ==================== CORE HTTP ====================

    private void sendRequest(final String action, final JSONObject params, final String callId) {
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... v) {
                try {
                    String timestamp = String.valueOf(System.currentTimeMillis());
                    params.put("action", action);
                    params.put("timestamp", timestamp);
                    params.put("device_token", deviceToken);
                    params.put("sig", hmac(action + timestamp + secretKey));

                    URL url = new URL(serverUrl + "src_mysql_api.php");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                    conn.setRequestProperty("X-SRC-Client", "SRCMySQL-Android-2.0");
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(connectTimeout);
                    conn.setReadTimeout(readTimeout);

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(params.toString().getBytes("UTF-8"));
                    }

                    int code = conn.getResponseCode();
                    InputStream is = (code >= 200 && code < 300)
                            ? conn.getInputStream() : conn.getErrorStream();

                    BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                    return sb.toString();

                } catch (Exception e) {
                    return "{\"success\":false,\"error\":\"Network error: " + e.getMessage() + "\",\"count\":0}";
                }
            }

            @Override
            protected void onPostExecute(String result) {
                try {
                    JSONObject json = new JSONObject(result);
                    if (json.optBoolean("success", false)) {
                        String data = json.optString("data", "[]");
                        int count  = json.optInt("count", 0);
                        OnSuccess(callId, data, count);
                    } else {
                        OnError(callId, json.optString("error", "Unknown error"));
                    }
                } catch (Exception e) {
                    OnError(callId, "Response parse error: " + e.getMessage()
                            + (debugMode ? " | Raw: " + result : ""));
                }
            }
        }.execute();
    }

    // ==================== AUTH ====================

    @SimpleFunction(description = "Authenticate your app with the server. Call this on app start. Listen to OnAuthenticated event.")
    public void Authenticate(final String appId) {
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... v) {
                try {
                    String ts  = String.valueOf(System.currentTimeMillis());
                    String sig = hmac(appId + ts + secretKey);

                    JSONObject body = new JSONObject();
                    body.put("action", "auth");
                    body.put("app_id", appId);
                    body.put("timestamp", ts);
                    body.put("sig", sig);

                    URL url = new URL(serverUrl + "src_mysql_api.php");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(connectTimeout);
                    conn.getOutputStream().write(body.toString().getBytes("UTF-8"));

                    BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), "UTF-8"));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                    return sb.toString();
                } catch (Exception e) {
                    return "{\"success\":false,\"error\":\"" + e.getMessage() + "\"}";
                }
            }

            @Override
            protected void onPostExecute(String result) {
                try {
                    JSONObject json = new JSONObject(result);
                    if (json.optBoolean("success", false)) {
                        deviceToken = json.optString("token", "");
                        int expires = json.optInt("expires_in", 3600);
                        OnAuthenticated(deviceToken, expires);
                    } else {
                        OnError("auth", json.optString("error", "Authentication failed"));
                    }
                } catch (Exception e) {
                    OnError("auth", "Auth error: " + e.getMessage());
                }
            }
        }.execute();
    }

    @SimpleFunction(description = "Manually set a previously saved session token (to avoid re-authentication).")
    public void SetToken(String token) {
        this.deviceToken = token;
    }

    @SimpleFunction(description = "Get current session token (save it for reuse).")
    public String GetToken() {
        return deviceToken;
    }

    // ==================== TABLE OPERATIONS ====================

    @SimpleFunction(description = "Create a new table.\ncolumns example: 'id INT AUTO_INCREMENT PRIMARY KEY, name TEXT NOT NULL, age INT, email VARCHAR(100) UNIQUE'")
    public void CreateTable(String tableName, String columns, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("columns", columns);
            sendRequest("create_table", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "Drop (delete) a table permanently. Be careful!")
    public void DropTable(String tableName, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            sendRequest("drop_table", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "Get list of all tables in the database. Result in OnSuccess data as JSON array.")
    public void ListTables(String callId) {
        try {
            sendRequest("list_tables", new JSONObject(), callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    // ==================== ROW OPERATIONS ====================

    @SimpleFunction(description = "Insert a new row.\ndataJson example: '{\"name\":\"Ram Kumar\",\"age\":25,\"city\":\"Meerut\"}'")
    public void InsertRow(String tableName, String dataJson, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("data", new JSONObject(dataJson));
            sendRequest("insert", p, callId);
        } catch (Exception e) { OnError(callId, "InsertRow error: " + e.getMessage()); }
    }

    @SimpleFunction(description = "Update existing rows.\ndataJson = '{\"name\":\"New Name\"}'\ncondition = 'id=5' or 'city=Meerut'")
    public void UpdateRow(String tableName, String dataJson, String condition, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("data", new JSONObject(dataJson));
            p.put("condition", condition);
            sendRequest("update", p, callId);
        } catch (Exception e) { OnError(callId, "UpdateRow error: " + e.getMessage()); }
    }

    @SimpleFunction(description = "Delete rows matching condition.\ncondition = 'id=5' or 'status=inactive'.\nAlways required for safety.")
    public void DeleteRow(String tableName, String condition, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("condition", condition);
            sendRequest("delete", p, callId);
        } catch (Exception e) { OnError(callId, "DeleteRow error: " + e.getMessage()); }
    }

    // ==================== QUERY OPERATIONS ====================

    @SimpleFunction(description = "Get all rows with pagination.\norderBy = column name (or empty)\nlimit = rows per page (0 = unlimited)\noffset = starting position")
    public void GetAllRows(String tableName, String orderBy, int limit, int offset, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("order_by", orderBy);
            p.put("limit", limit);
            p.put("offset", offset);
            sendRequest("get_all", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "Search rows with conditions.\ncondition = 'age>18 AND city=Meerut'\nSupports: =, !=, >, <, >=, <=, AND, OR")
    public void SearchRows(String tableName, String condition, String orderBy,
                           int limit, int offset, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("condition", condition);
            p.put("order_by", orderBy);
            p.put("limit", limit);
            p.put("offset", offset);
            sendRequest("search", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "LIKE search for partial matches.\npattern examples: '%Ram%' (contains), 'Ram%' (starts with), '%Ram' (ends with)")
    public void LikeSearch(String tableName, String column, String pattern,
                           int limit, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("column", column);
            p.put("pattern", pattern);
            p.put("limit", limit);
            sendRequest("like_search", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "Get COUNT / SUM / AVG / MAX / MIN of a column.\nfunc = COUNT, SUM, AVG, MAX, MIN\ncondition = optional filter (or empty)")
    public void Aggregate(String tableName, String column, String func,
                          String condition, String callId) {
        try {
            JSONObject p = new JSONObject();
            p.put("table", tableName);
            p.put("column", column);
            p.put("func", func);
            p.put("condition", condition);
            sendRequest("aggregate", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    @SimpleFunction(description = "Run a custom SELECT query. Only SELECT is allowed for security.\nexample: 'SELECT name, age FROM users WHERE age > 18 ORDER BY name LIMIT 10'")
    public void CustomQuery(String selectQuery, String callId) {
        if (!selectQuery.trim().toUpperCase().startsWith("SELECT")) {
            OnError(callId, "Only SELECT queries are allowed in CustomQuery for security.");
            return;
        }
        try {
            JSONObject p = new JSONObject();
            p.put("query", selectQuery);
            sendRequest("custom_query", p, callId);
        } catch (Exception e) { OnError(callId, e.getMessage()); }
    }

    // ==================== JSON HELPERS ====================

    @SimpleFunction(description = "Get a value from JSON array by row index and column name.\nExample: GetValue('[{\"name\":\"Ram\"}]', 0, 'name') → 'Ram'")
    public String GetValue(String jsonArray, int rowIndex, String columnName) {
        try {
            JSONArray arr = new JSONArray(jsonArray);
            if (rowIndex < arr.length()) {
                return arr.getJSONObject(rowIndex).optString(columnName, "");
            }
        } catch (Exception ignored) {}
        return "";
    }

    @SimpleFunction(description = "Get total row count from JSON array string.")
    public int GetRowCount(String jsonArray) {
        try { return new JSONArray(jsonArray).length(); }
        catch (Exception e) { return 0; }
    }

    @SimpleFunction(description = "Convert one column from JSON array to a List (for ListViewer, Spinner, etc).\nExample: JsonToList('[{\"name\":\"Ram\"},{\"name\":\"Shyam\"}]', 'name') → [Ram, Shyam]")
    public YailList JsonToList(String jsonArray, String columnName) {
        List<String> list = new ArrayList<>();
        try {
            JSONArray arr = new JSONArray(jsonArray);
            for (int i = 0; i < arr.length(); i++) {
                list.add(arr.getJSONObject(i).optString(columnName, ""));
            }
        } catch (Exception ignored) {}
        return YailList.makeList(list);
    }

    @SimpleFunction(description = "Convert JSON array to CSV string.\nUseful for sharing data.\nExample: JsonToCsv('[{\"name\":\"Ram\",\"age\":\"25\"}]') → 'name,age\\nRam,25'")
    public String JsonToCsv(String jsonArray) {
        try {
            JSONArray arr = new JSONArray(jsonArray);
            if (arr.length() == 0) return "";
            JSONObject first = arr.getJSONObject(0);
            List<String> headers = new ArrayList<>();
            Iterator<String> keys = first.keys();
            while (keys.hasNext()) headers.add(keys.next());

            StringBuilder sb = new StringBuilder(String.join(",", headers)).append("\n");
            for (int i = 0; i < arr.length(); i++) {
                JSONObject row = arr.getJSONObject(i);
                List<String> vals = new ArrayList<>();
                for (String h : headers) vals.add(row.optString(h, "").replace(",", " "));
                sb.append(String.join(",", vals)).append("\n");
            }
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    @SimpleFunction(description = "Build a simple JSON string for InsertRow/UpdateRow.\nkeys and values must be same-length comma-separated strings.\nExample: MakeJson('name,age', 'Ram,25') → '{\"name\":\"Ram\",\"age\":\"25\"}'")
    public String MakeJson(String keys, String values) {
        try {
            String[] ks = keys.split(",");
            String[] vs = values.split(",", -1);
            JSONObject obj = new JSONObject();
            for (int i = 0; i < ks.length; i++) {
                obj.put(ks[i].trim(), i < vs.length ? vs[i].trim() : "");
            }
            return obj.toString();
        } catch (Exception e) { return "{}"; }
    }

    @SimpleFunction(description = "Get the insert_id from last InsertRow success response.")
    public String GetInsertId(String successData) {
        try { return new JSONObject(successData).optString("insert_id", "0"); }
        catch (Exception e) { return "0"; }
    }

    @SimpleFunction(description = "Get aggregate result value from Aggregate() success response.")
    public String GetAggregateResult(String successData) {
        try { return new JSONObject(successData).optString("result", "0"); }
        catch (Exception e) { return "0"; }
    }
}
