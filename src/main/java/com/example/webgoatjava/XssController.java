package com.example.webgoatjava;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssController {

    // 1) Reflected XSS - raw reflection
    @GetMapping("/xss/reflected")
    public String reflected(@RequestParam(defaultValue = "Hello") String q) {
        return "<h1>Search</h1><div>Query: " + q + "</div>"; // vulnerable
    }

    // 2) Reflected XSS - another raw reflection
    @GetMapping("/xss/echo")
    public String echo(@RequestParam(defaultValue = "Hello") String msg) {
        return "<p>You said: " + msg + "</p>"; // vulnerable
    }

    // 3) Weak custom sanitizer with "escape" name
    @GetMapping("/xss/weak")
    public String weak(@RequestParam(defaultValue = "Hi") String input) {
        String escaped = escape(input); // looks safe but isn't
        return "<div>Weak escaped: " + escaped + "</div>";
    }

    // Only strips angle brackets; does not encode quotes, slashes, event handlers, etc.
    private String escape(String s) {
        if (s == null) return "";
        return s.replace("<", "&lt;").replace(">", "&gt;"); // still vulnerable
    }
}
