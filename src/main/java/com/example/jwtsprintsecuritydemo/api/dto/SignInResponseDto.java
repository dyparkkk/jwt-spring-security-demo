package com.example.jwtsprintsecuritydemo.api.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignInResponseDto {
    private String accessToken;
    private String refreshToken;

}

