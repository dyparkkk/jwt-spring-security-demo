package com.example.jwtsprintsecuritydemo.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthController {

    @GetMapping("/auth/test")
    public String test() { // @AuthenticationPrincipal
        log.info("-------/auth/test");
        return "auth";
    }
}
