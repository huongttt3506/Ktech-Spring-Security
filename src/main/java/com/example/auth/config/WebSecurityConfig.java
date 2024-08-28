package com.example.auth.config;

import com.example.auth.filters.AlwaysAuthenticatedFilter;
import com.example.auth.filters.JwtTokenFilter;
import com.example.auth.jwt.JwtTokenUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
public class WebSecurityConfig {
    private final JwtTokenUtils tokenUtils;

    public WebSecurityConfig(JwtTokenUtils tokenUtils) {
        this.tokenUtils = tokenUtils;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {
        // URL에 따라 접근 권한을 조정하는 방법
        http
                // CSRF  (Cross-Site Request Forgery): bảo vệ endpoint khỏi attacker.
                //Trong TH này, disable: tắt, không kiểm tra các mã thông báo CSRF trong các yêu cầu HTTP
                .csrf(AbstractHttpConfigurer::disable)
                // Chỉ định chính sách truy cập
                .authorizeHttpRequests(auth -> {
                    // cho phép tất cả ng dùng truy cập: /no-auth, / , /token/...
                    auth.requestMatchers("/no-auth", "/", "/token/issue", "/error")
                            .permitAll();

                    // 인증이 된 사용자만 허용하는 URL
                    // authenticated: yêu cầu xác thực
                    auth.requestMatchers("/users/my-profile")
                            .authenticated();

                    // những người dùng chưa xác thực.
                    auth.requestMatchers("/users/register")
                            .anonymous();

//                    auth.requestMatchers(HttpMethod.POST, "/articles")
//                            .authenticated();
//                    auth.requestMatchers(HttpMethod.GET, "/articles")
//                            .permitAll();
                    // /articles, /articles/1, /articles/1/update
                    auth.requestMatchers("/articles/**", "token/is-authenticated")
                            .authenticated();
//                    auth.requestMatchers("/")
//                            .permitAll();
//                    auth.requestMatchers("/nobody")
//                            .denyAll();
                })

                // 로그인은 어떤 URL에서 어떤 방식으로 이뤄지는지
                //cấu hình đăng nhập
                .formLogin(formLogin -> formLogin
                        .loginPage("/users/login")
                        //url nếu login thành công thì chuyển hướng đến
                        .defaultSuccessUrl("/users/my-profile")
                        // url nếu login không thành công
                        .failureUrl("/users/login?fail")
                        // tất cả người dùng đều truy cập được
                        .permitAll()
                )

                // cấu hình logout
                .logout(logout -> logout
                        //url đăng xuất
                        .logoutUrl("/users/logout")
                        // sau khi đăng xuất thì chuyển hướng đến /users/login
                        .logoutSuccessUrl("/users/login")
                )

                // thêm bộ lọc tùy chỉnh AlwaysAuthenticatedFilter,
                // trước AuthorizationFilter trong filterchain.
                .addFilterBefore(
//                        new AlwaysAuthenticatedFilter(),
                        new JwtTokenFilter(tokenUtils),
                        AuthorizationFilter.class
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        ;

        // before 6.1
        /*
        http.authorizeHttpRequests()
                .requestMatchers("/no-auth")
                .permitAll()
                .and();
         */

        return http.build();
    }

//    @Bean
//    public UserDetailsManager userDetailsManager(
//            PasswordEncoder passwordEncoder
//    ) {
//        UserDetails user1 = User.withUsername("user1")
//                .password(passwordEncoder.encode("password"))
//                .build();
//        return new InMemoryUserDetailsManager(user1);
//    }
    // MÃ HÓA MẬT KHẨU
    @Bean
    public PasswordEncoder passwordEncoder() {
        // sữ dụng thuật toán BCrypt để econder password
        return new BCryptPasswordEncoder();
    }
}