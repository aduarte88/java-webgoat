package com.example.webgoatjava;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DbController {

    // 1) Connection String Injection
    @GetMapping("/db/connect")
    public String connect(@RequestParam String host,
                          @RequestParam String db,
                          @RequestParam(required = false, defaultValue = "") String params) {
        String url = "jdbc:postgresql://" + host + "/" + db + (params.isEmpty() ? "" : "?" + params);
        // In a real app this would be used to open a connection; we just return it for demo.
        return "Connecting to: " + url; // vulnerable to injection via params (e.g., ;user=...;password=...)
    }
}
