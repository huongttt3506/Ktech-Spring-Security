package com.example.auth;

import com.example.auth.entity.CustomUserDetails;
import com.example.auth.repo.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;



@Slf4j
@Controller
@RequestMapping("users")
public class UserController {
    private final PasswordEncoder passwordEncoder;
//    private final UserDetailsManager manager;
    private final UserService service;

    public UserController(
            PasswordEncoder passwordEncoder,
            UserService service
//            UserDetailsManager manager
    ) {
        this.passwordEncoder = passwordEncoder;
//        this.manager = manager;
        this.service = service;
    }

    @GetMapping("login")
    public String loginForm() {
        return "login-form";
    }

    @GetMapping("my-profile")
    public String myProfile(
            Authentication authentication
    ) {
        log.info(authentication.getName());
//        log.info(((User) authentication.getPrincipal()).getUsername());
        if (authentication.getPrincipal() instanceof CustomUserDetails details) {
            log.info(details.getEmail());
            log.info(details.getPhone());
        }
//        CustomUserDetails details = (CustomUserDetails) authentication.getPrincipal();

        return "my-profile";
    }

    @GetMapping("register")
    public String signUpForm() {
        return "register-form";
    }

    @PostMapping("register")
    public String signUpRequest(
            @RequestParam("username")
            String username,
            @RequestParam("password")
            String password,
            @RequestParam("password-check")
            String passwordCheck
    ) {
        if (password.equals(passwordCheck)) {
//            manager.createUser(User.withUsername(username)
//                    .password(passwordEncoder.encode(password))
//                    .build());
            service.createUser(username, password, passwordCheck);
        }
        return "redirect:/users/login";
    }
}