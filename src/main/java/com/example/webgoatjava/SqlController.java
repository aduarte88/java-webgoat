package com.example.webgoatjava;

import org.apache.commons.lang3.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Intentionally vulnerable SQL examples that actually execute against H2 (in-memory).
 */
@RestController
public class SqlController {

    private String runPreparedQuery(String sql, String param) {
        java.util.List<String> rows = new java.util.ArrayList<>();
        try (java.sql.Connection conn = dataSource.getConnection();
             java.sql.PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, param);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(rs.getInt("id") + ":" + rs.getString("username") + ":" + rs.getString("name"));
                }
            }
        } catch (Exception e) {
            return "ERROR: " + e.getMessage() + " | QUERY: " + sql + " | PARAM: " + param;
        }
        return "RESULTS(" + rows.size() + ") QUERY: " + sql + " | PARAM: " + param + " | ROWS: " + String.join(", ", rows);
    }


    @Autowired
    private DataSource dataSource;

    private String runQuery(String query) {
        List<String> rows = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(query)) {
            while (rs.next()) {
                rows.add(rs.getInt("id") + ":" + rs.getString("username") + ":" + rs.getString("name"));
            }
        } catch (Exception e) {
            return "ERROR: " + e.getMessage() + " | QUERY: " + query;
        }
        return "RESULTS(" + rows.size() + ") QUERY: " + query + " | ROWS: " + String.join(", ", rows);
    }

    // 1) Basic concatenation (SQL Injection)
    @GetMapping("/sql/basic")
    public String basic(@RequestParam(defaultValue = "alice") String username) {
        String query = "SELECT id, username, name FROM users WHERE username = '" + username + "'";
        return runQuery(query); // vulnerable: attacker controls 'username'
    }

    // 2) Misuse of escapeSql (deprecated; not a full SQLi mitigation)
    @GetMapping("/sql/escape")
    public String escape(@RequestParam(defaultValue = "bob") String username) {
        String escaped = StringEscapeUtils.escapeSql(username); // ineffective
        String query = "SELECT id, username, name FROM users WHERE username = '" + escaped + "'";
        return runQuery(query); // still vulnerable under many conditions
    }

    // 3) Weak regex blacklist (easy to bypass)
    @GetMapping("/sql/regex")
    public String regex(@RequestParam(defaultValue = "carol") String username) {
        String cleaned = username.replaceAll("[';]", ""); // naive
        String query = "SELECT id, username, name FROM users WHERE username = '" + cleaned + "'";
        return runQuery(query); // vulnerable to many bypasses
    }
}


// 4) Secure example using PreparedStatement (not vulnerable)
@GetMapping("/sql/prepared")
public String prepared(@RequestParam(defaultValue = "alice") String username) {
    List<String> rows = new ArrayList<>();
    String query = "SELECT id, username, name FROM users WHERE username = ?";
    try (Connection conn = dataSource.getConnection();
         java.sql.PreparedStatement ps = conn.prepareStatement(query)) {
        ps.setString(1, username);
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.add(rs.getInt("id") + ":" + rs.getString("username") + ":" + rs.getString("name"));
            }
        }
    } catch (Exception e) {
        return "ERROR: " + e.getMessage();
    }
    return "SAFE RESULTS(" + rows.size() + ") for username=" + username + " | ROWS: " + String.join(", ", rows);

    // SAFE example using PreparedStatement
    @GetMapping("/sql/safe")
    public String safe(@RequestParam(defaultValue = "alice") String username) {
        String sql = "SELECT id, username, name FROM users WHERE username = ?";
        return runPreparedQuery(sql, username);
    }
}
