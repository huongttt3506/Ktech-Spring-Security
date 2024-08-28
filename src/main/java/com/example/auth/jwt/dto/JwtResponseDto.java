package com.example.auth.jwt.dto;

import lombok.Data;
// chứa token JWT khi phản hồi lại cho client.
@Data
public class JwtResponseDto {
    private String token;

}
