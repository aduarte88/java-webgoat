package com.example.webgoatjava;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecretsController {

    // Hardcoded secret (3 of 3)
    private static final String MASTER_PASSWORD = "P@ssw0rd123!"; // intentionally hardcoded

    @GetMapping("/secrets/show")
    public String show() {
        String ftpUser = "deploy";
        String ftpPass = "Sup3rSecret!"; // another hardcoded example in code path
        return "Master=" + MASTER_PASSWORD + ", ftp=" + ftpUser + ":" + ftpPass;
    }
}
