package com.example.jwtsprintsecuritydemo.service;

import com.example.jwtsprintsecuritydemo.api.dto.SignInResponseDto;
import com.example.jwtsprintsecuritydemo.domain.Member;
import com.example.jwtsprintsecuritydemo.repository.MemberRepository;
import com.example.jwtsprintsecuritydemo.repository.RefreshTokenRepository;
import com.example.jwtsprintsecuritydemo.security.MyUserDetailsService;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
@Slf4j
public class LoginService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final MyUserDetailsService myUserDetailsService;
    private final RefreshTokenRepository repository; // 삭제

    @Transactional
    public Long signUp(String userId, String pw){ // 회원가입
        // 중복체크
        validateDuplicateUser(userId);
        String encodePw = passwordEncoder.encode(pw);

        return memberRepository.save(Member.testCreate(userId, encodePw)).getId();
    }

    @Transactional()
    public SignInResponseDto signIn(String userId, String pw) {
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(userId);

        if(!passwordEncoder.matches(pw, userDetails.getPassword())){
            throw new BadCredentialsException(userDetails.getUsername() + "Invalid password");
        }

        Authentication authentication =  new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());

        log.info("signIn service | authentication.getName : {}, authentication.getCredentials() : {}",
                authentication.getName(), authentication.getCredentials());

        return new SignInResponseDto(
                "Bearer-"+jwtTokenProvider.createAccessToken(authentication),
                "Bearer-"+jwtTokenProvider.issueRefreshToken(authentication));
    }

    private void validateDuplicateUser(String userId){
        memberRepository.findByUserId(userId)
                .ifPresent(member -> {
                    log.debug("userId : {}, 아이디 중복으로 회원가입 실패", userId);
                    throw new RuntimeException("아이디 중복");
                });
    }
}
