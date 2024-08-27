package com.example.auth.filters;

import com.example.auth.entity.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

// 이 필터가 등록되면 모든 요청은 인증된 요청이라고 판단한다.
@Slf4j
public class AlwaysAuthenticatedFilter extends OncePerRequestFilter
// extends OncePerRequestFilter( that filter is just called once time for each httpRequest)
{
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            // continue next filter when that filter done
            FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("try all auth filter");
        // Spring Security 내부적으로 인증 정보를 담고있는 객체
        // SecurityContext: where Spring Security store auth info for current session
        SecurityContext context = SecurityContextHolder
                .createEmptyContext();

        //AbstractAuthenticationToken: Lớp cơ bản cho các token chứa thông tin xác thực.
        AbstractAuthenticationToken authentication =
                // x thực dựa trên username và password
                new UsernamePasswordAuthenticationToken(
                        new CustomUserDetails(
                                1L,
                                "alex",
                                "password",
                                "a@a.a",
                                "010-abcd-ef01"
                        ),
                        "password",
                        new ArrayList<>()
                );
        //Gán đối tượng xác thực authentication vào SecurityContext.
        context.setAuthentication(authentication);

        //Đặt SecurityContext chứa đối tượng xác thực này vào SecurityContextHolder
        // để Spring Security có thể truy cập và sử dụng trong các bước tiếp theo.
        SecurityContextHolder.setContext(context);
        // continue ...(go next filter)  // 검사에 통과하지 않아도 다음 필터를 실행한다.
        filterChain.doFilter(request, response);
    }
}