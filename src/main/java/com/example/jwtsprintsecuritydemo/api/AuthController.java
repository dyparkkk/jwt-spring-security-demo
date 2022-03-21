package com.example.jwtsprintsecuritydemo.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AuthController {

    @GetMapping("/auth/test")
    public String test(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("--/auth/test-- | userId : {}, Role : {}",
                userDetails.getUsername(), userDetails.getAuthorities());
        return "success auth";
    }
}
