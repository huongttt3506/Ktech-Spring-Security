package com.example.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    // /no-auth 로 들어오는 용칭은
    // 사용자 login
    @GetMapping("/no-auth")
    public String noAuth() {
        return "no auth success!";
    }
}
