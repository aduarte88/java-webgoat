package com.example.webgoatjava;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Privacy violation: first persist sensitive data, then log it (bad practice).
 */
@RestController
public class PrivacyController {

    private static final Logger log = LoggerFactory.getLogger(PrivacyController.class);

    @Autowired
    private JdbcTemplate jdbc;

    // 1) Store SSN then log it
    @GetMapping("/privacy/ssn")
    public String storeAndLogSsn(@RequestParam("ssn") String ssn) {
        jdbc.update("INSERT INTO pii (ssn) VALUES (?)", ssn);
        log.info("Stored SSN (PII): {}", ssn); // privacy violation: logging PII
        return "stored";
    }

    // 2) Store credit card number then log it
    @GetMapping("/privacy/card")
    public String storeAndLogCard(@RequestParam("creditCardNumber") String creditCardNumber) {
        jdbc.update("INSERT INTO pii (credit_card_number) VALUES (?)", creditCardNumber);
        log.info("Stored CreditCard (PII): {}", creditCardNumber); // privacy violation
        return "stored";
    }

    // 3) Store email then log it (still PII)
    @GetMapping("/privacy/email")
    public String storeAndLogEmail(@RequestParam("email") String email) {
        jdbc.update("INSERT INTO pii (email) VALUES (?)", email);
        log.info("Stored Email (PII): {}", email);
        return "stored";
    }
}
