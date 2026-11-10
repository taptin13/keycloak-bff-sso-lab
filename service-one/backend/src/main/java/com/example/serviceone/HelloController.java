package com.example.serviceone;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/api/hello")
    HelloResponse hello(@AuthenticationPrincipal Jwt jwt) {
        return new HelloResponse("service-one", jwt.getClaimAsString("preferred_username"));
    }

    record HelloResponse(String service, String username) {
    }
}
