package com.example.jwtsprintsecuritydemo.security.config;

import com.example.jwtsprintsecuritydemo.security.jwt.JwtAccessDeniedHandler;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtAuthenticationEntryPoint;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtTokenFilterConfigurer;
import com.example.jwtsprintsecuritydemo.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 이게 뭐임?
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
//                .antMatchers(HttpMethod.OPTIONS, "/**") // 이게 뭐임?
                .antMatchers(
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/h2-console/**"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                //session 사용 안함
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)


                .and()
                .authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/auth/**").authenticated()
                .anyRequest().permitAll()

                .and()
                .apply(new JwtTokenFilterConfigurer(jwtTokenProvider));

    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
