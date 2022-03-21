package com.example.jwtsprintsecuritydemo.service;

import com.example.jwtsprintsecuritydemo.api.dto.TokenResponseDto;
import com.example.jwtsprintsecuritydemo.domain.Member;
import com.example.jwtsprintsecuritydemo.redis.RefreshRedisRepository;
import com.example.jwtsprintsecuritydemo.redis.RefreshRedisToken;
import com.example.jwtsprintsecuritydemo.repository.MemberRepository;
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
    private final RefreshRedisRepository refreshRedisRepository;

    @Transactional
    public Long signUp(String userId, String pw){ // 회원가입
        // 중복체크
        validateDuplicateUser(userId);
        String encodePw = passwordEncoder.encode(pw);

        return memberRepository.save(Member.testCreate(userId, encodePw)).getId();
    }

    @Transactional(readOnly = true)
    public TokenResponseDto signIn(String userId, String pw) {
        // uesrId 확인
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(userId);

        // pw 확인
        if(!passwordEncoder.matches(pw, userDetails.getPassword())){
            throw new BadCredentialsException(userDetails.getUsername() + "Invalid password");
        }

        Authentication authentication =  new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());

        // refresh token 발급 및 저장
        String refreshToken = jwtTokenProvider.createRefreshToken(authentication);
        RefreshRedisToken token = RefreshRedisToken.createToken(userId, refreshToken);

        // 기존 토큰이 있으면 수정, 없으면 생성
        refreshRedisRepository.save(token);

        // accessToken과 refreshToken 리턴
        return TokenResponseDto.builder()
                .accessToken("Bearer-"+jwtTokenProvider.createAccessToken(authentication))
                .refreshToken("Bearer-"+refreshToken)
                .build();
    }

    private void validateDuplicateUser(String userId){
        memberRepository.findByUserId(userId)
                .ifPresent(member -> {
                    log.debug("userId : {}, 아이디 중복으로 회원가입 실패", userId);
                    throw new RuntimeException("아이디 중복");
                });
    }

    @Transactional(readOnly = true)
    public TokenResponseDto reissueAccessToken(String token) {

        //token 앞에 "Bearer-" 제거
        String resolveToken = resolveToken(token);

        //토큰 검증 메서드
        //실패시 jwtTokenProvider.validateToken(resolveToken) 에서 exception을 리턴함
        jwtTokenProvider.validateToken(resolveToken);

        Authentication authentication = jwtTokenProvider.getAuthentication(resolveToken);
        // 디비에 있는게 맞는지 확인
        RefreshRedisToken refreshRedisToken = refreshRedisRepository.findById(authentication.getName()).get();

        // 토큰이 같은지 확인
        if(!resolveToken.equals(refreshRedisToken.getToken())){
            throw new RuntimeException("not equals refresh token");
        }

        // 재발행해서 저장
        String newToken = jwtTokenProvider.createRefreshToken(authentication);
        RefreshRedisToken newRedisToken = RefreshRedisToken.createToken(authentication.getName(), newToken);
        refreshRedisRepository.save(newRedisToken);

        // accessToken과 refreshToken 모두 재발행
        return TokenResponseDto.builder()
                .accessToken("Bearer-"+jwtTokenProvider.createAccessToken(authentication))
                .refreshToken("Bearer-"+newToken)
                .build();
    }

    //token 앞에 "Bearer-" 제거
    private String resolveToken(String token){
        if(token.startsWith("Bearer-"))
            return token.substring(7);
        throw new RuntimeException("not valid refresh token !!");
    }
}
