package com.example.jwtsprintsecuritydemo.api;

import com.example.jwtsprintsecuritydemo.api.dto.TokenResponseDto;
import com.example.jwtsprintsecuritydemo.service.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ApiController {

    private final LoginService loginService;

    @PostMapping("/api/v1/signUp")
    public Long signUp(@RequestParam String id,
                       @RequestParam String pw) {
        return loginService.signUp(id, pw);
    }

    @PostMapping("/api/v1/signIn")
    public TokenResponseDto signInp(@RequestParam String id,
                                    @RequestParam String pw) {
        return loginService.signIn(id, pw);
    }

    /**
     * Access token이 만료되었을 경우 프론트에서 요청할 api
     * @param token : Refresh token을 입력받는다.
     * @return TokenResponseDto : Access token과 Refresh token 모두 재발급해준다.
     */
    @PostMapping("/api/v1/accessToken")
    public TokenResponseDto reissueAccessToken(@RequestParam String token){
       return loginService.reissueAccessToken(token);
    }
}

