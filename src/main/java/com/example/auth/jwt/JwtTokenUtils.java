package com.example.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
// JwtTokenUtils là một lớp hỗ trợ thao tác với JWT (tạo, xác thực, và giải mã token).
@Slf4j
@Component
public class JwtTokenUtils {
    // JWT 암호키를 담기 위한 객체 (khóa dùng để kí jwt)
    private final Key secretKey;
    // JWT를 해석하는 객체 (Parser dùng để phân tích, xacs thực jwt)
    private final JwtParser jwtParser;

    // Constructor này tạo ra một khóa ký (secretKey)
    // và một đối tượng JwtParser để sử dụng trong việc ký và phân tích JWT.
    public JwtTokenUtils(
            // đặt giá trị jwt.secret từ file yaml vào biến jwtSecret
            @Value("${jwt.secret}")
            String jwtSecret
    ) {
        log.info("jwtSecret: {}", jwtSecret);
        // tạo secretKey bằng thuật toán HMAC với jwtSecret
        this.secretKey =
                Keys.hmacShaKeyFor(jwtSecret.getBytes());
        // giải mã
        this.jwtParser = Jwts
                .parserBuilder() // tạo 1 JwtParse builder
                .setSigningKey(this.secretKey) // thiết lập khóa kí để xác thực chữ kí jwt
                .build(); // xây dựng JwtParser
    }

    public String generateToken(UserDetails userDetails) {
        // 현재시각을 기준으로 만료 시각을 정해야 함으로, 현재 시각을 구한다.
        Instant now = Instant.now();  // Lấy thời gian hiện tại.
        Claims jwtClaims = Jwts.claims()
                // 이 JWT를 들고있는 사람이 누구인지
                .setSubject(userDetails.getUsername()) // Thiết lập chủ thể (subject) của JWT là tên người dùng.
                // 이 JWT가 언제 생성되었는지
                .setIssuedAt(Date.from(now)) // Thiết lập thời gian phát hành JWT.
                // 이 JWT가 언제 만료되는지
//                .setExpiration(Date.from(now.plusSeconds(60 * 60 * 24))); // thiết lập thời gian hết hạn (1 ngày)
                .setExpiration(Date.from(now.plusSeconds(60))); //10 giây

        return Jwts.builder()
                .setClaims(jwtClaims) // Thiết lập các claims đã tạo ở trên.
                .signWith(this.secretKey) // Ký JWT bằng khóa đã tạo.
                .compact(); // Tạo chuỗi JWT.
    }

    //Phương thức xác thực JWT

    public boolean validate(String token) {
        try {
            Claims claims = jwtParser.parseClaimsJws(token)
                    .getBody(); // Phân tích JWT và lấy phần thân (body) chứa các claims.
            log.info("subject: {}", claims.getSubject()); // là ai?
            log.info("issuedAt: {}", claims.getIssuedAt()); // thời gian phát hành?
            log.info("expireAt: {}", claims.getExpiration()); // hết hạn?
            return true;
        } catch (Exception e) {
            log.warn("invalid jwt provided: {}", e.getMessage());
        }
        return false; // trả về 'false' nếu JWT không hợp lệ.
    }

    // Phương thức phân tích JWT và lấy thông tin
    public Claims parseClaims(String token) {
        return jwtParser // Sử dụng `jwtParser` để phân tích JWT.
                .parseClaimsJws(token)  // Phân tích JWT.
                .getBody();  // Lấy phần thân (body) của JWT, chứa các claims.
    }
}