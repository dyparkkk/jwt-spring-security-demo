package com.example.jwtsprintsecuritydemo.config;

import com.example.jwtsprintsecuritydemo.security.jwt.JwtAccessDeniedHandler;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtAuthenticationEntryPoint;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtTokenFilterConfigurer;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 *  security 5.7 이후로 WebSecurityConfigurerAdapter가 Deprecated 되었습니다 !!
 * 따라서 이제는 filterChain( 전 configure) 메소드 작성시 @Override 대신 @Bean에 등록해서 사용합니다
 * 개인적으로 조금 더 스프링스럽게 바뀌었다고 생각하고 코드가 깔금해져서 좋습니다.
 * 자세한 내용은 https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter 참고
 */
@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring()
//                .antMatchers("/", "/*.html", "/favicon.ico", "/h2-console/**");
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/**").permitAll()
                        .requestMatchers("/auth/**").authenticated()
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults()); // ?
        http
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler);
        http
                .apply(new JwtTokenFilterConfigurer(jwtTokenProvider));

        return http.build();
    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                //session 사용 안함
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//
//                .and()
//                .exceptionHandling()
//                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 인증 실패시 오류 처리
//                .accessDeniedHandler(jwtAccessDeniedHandler)  // 권한 부족시 오류 처리
//
//                .and()
//                .authorizeRequests()
//                .antMatchers("/api/**").permitAll()
//                .antMatchers("/auth/**").authenticated()
//                .anyRequest().permitAll()
//
//                .and()
//                .apply(new JwtTokenFilterConfigurer(jwtTokenProvider)); // JWT 관련 필터 추가
//    }

    // 비밀번호 암호와 객체 빈 추가
    @Bean
    public PasswordEncoder passwordEncoder(){
        // return new BCryptPasswordEncoder();
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

//    @Bean  // 인증 실패 처리 관련 객체 추가
//    @Override public AuthenticationManager authenticationManagerBean() throws Exception {
//        return super.authenticationManagerBean();
//    }
}
