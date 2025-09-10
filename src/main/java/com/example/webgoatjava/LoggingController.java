package com.example.webgoatjava;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoggingController {

    private static final Logger log = LoggerFactory.getLogger(LoggingController.class);

    // 1) Log Forging via 'event' parameter (allows CRLF injection)
    @GetMapping("/log/event")
    public String logEvent(@RequestParam String event) {
        log.info("EVENT: " + event); // vulnerable: attacker-controlled content in logs
        return "logged";
    }

    // 2) Log Forging via 'name' parameter
    @GetMapping("/log/user")
    public String logUser(@RequestParam String name) {
        log.info("User login: " + name); // vulnerable
        return "ok";
    }
}
