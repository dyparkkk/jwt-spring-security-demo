# JWT using Spring Boot & Redis

[![license](https://img.shields.io/github/license/dyparkkk/jwt-spring-security-demo)](https://github.com/dyparkkk/jwt-spring-security-demo/blob/main/LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)


> Spring Security와JWT를 사용해서 만든 유저 인증 서비스. 
> 성능과 만료시간 설정 등의 편리함으로 인메모리 데이터 저장소인 redis를 간단하게 사용. 
> 로컬 환경에서 간단하게 사용 가능

## Table of Contents

- [알아두기](#알아두기)
- [기본 환경 구성 ](#기본-환경-구성)
- [주요 기능 객체 소개](#주요-기능-객체-소개)
- [Install](#Install)
- [Usage](#Usage)
- [API](#api)
- [JWT 고찰](#JWT-고찰)
- [참고자료](#참고자료)
- [License](#license)

## 알아두기

```
// build.gradle
implementation 'org.springframework.boot:spring-boot-starter-data-redis'
```
- Spring Data Redis
  - Redis를 JPA Repository처럼 이용가능 하게 인터페이스를 제공해주는 모듈
  - CrudRepository를 지원해서 좀 더 직관적으로 사용 가능

```
implementation group: 'it.ozimov', name: 'embedded-redis', version: '0.7.2'
```
- Embedded Redis
  - 내장 Redis 데몬 -> 로컬 환경에서 추가 데몬 설치없이 사용 가능

## 기본 환경 구성

### WebSecurityConfig
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/", "/*.html", "/favicon.ico", "/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                //session 사용 안함
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 인증 실패시 오류 처리
                .accessDeniedHandler(jwtAccessDeniedHandler)  // 권한 부족시 오류 처리

                .and()
                .authorizeRequests()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/auth/**").authenticated()
                .anyRequest().permitAll()

                .and()
                .apply(new JwtTokenFilterConfigurer(jwtTokenProvider)); // JWT 관련 필터 추가
    }

    // 비밀번호 암호와 객체 빈 추가
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean  // 인증 실패 처리 관련 객체 추가
    @Override public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

"/api/**" 로 시작하는 api는 항상 접근 가능하지만, "/auth/**" 로 시작하는 api는 권한이 있어야 접근 가능함 <br>
다시 말해서 정상 jwt token이 있어야 접근 가능

### RedisConfig & RefreshRedisRepository

```java
@Configuration
@EnableRedisRepositories
public class RedisConfig {

    @Value("${spring.redis.port}")
    private int port;

    @Value("${spring.redis.host}")
    private String host;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(host, port);
    }

    @Bean
    public RedisTemplate<?, ?> redisTemplate() {
        RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory());
        return redisTemplate;
    }
}
```
```java
public interface RefreshRedisRepository extends CrudRepository<RefreshRedisToken, String> {
}
```
redis를 사용하기 위한 설정을 담은 RedisConfig 와 jpa처럼 redis를 사용하기 위한 RefreshRedisRepository.

## 주요 기능 객체 소개

### JwtTokenProvider
```java
@Component
@Slf4j
public class JwtTokenProvider implements InitializingBean {

    private final MyUserDetailsService myUserDetailsService;

    private final String secretKey;
    private final long tokenValidityInMs;
    private final long refreshTokenValidityInMs;

    public JwtTokenProvider(@Value("${jwt.secret-key}") String secretKey,
                            @Value("${jwt.token-validity-in-sec}") long tokenValidity,
                            @Value("${jwt.refresh-token-validity-in-sec}") long refreshTokenValidity,
                            MyUserDetailsService myUserDetailsService){
        this.secretKey = secretKey;
        this.tokenValidityInMs = tokenValidity * 1000;
        this.refreshTokenValidityInMs = refreshTokenValidity * 1000;
        this.myUserDetailsService = myUserDetailsService;
    }

    private Key key;

    @Override
    public void afterPropertiesSet() throws Exception {  // init()
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        key = Keys.hmacShaKeyFor(encodedKey.getBytes());
        // https://budnamu.tistory.com/entry/JWT 참고
    }

    public String createAccessToken(Authentication authentication) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + tokenValidityInMs);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(now) // 발행시간
                .signWith(key, SignatureAlgorithm.HS512) // 암호화
                .setExpiration(validity) // 만료
                .compact();
    }

    /**
     * 토큰으로 부터 Authentication 객체를 얻어온다. 
     * Authentication 안에 user의 정보가 담겨있음.
     * UsernamePasswordAuthenticationToken 객체로 Authentication을 쉽게 만들수 있으며,
     * 매게변수로 UserDetails, pw, authorities 까지 넣어주면 
     * setAuthenticated(true)로 인스턴스를 생성해주고 
     * Spring-Security는 그것을 체크해서 로그인을 처리함
     */
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        UserDetails userDetails = myUserDetailsService.loadUserByUsername(claims.getSubject());
        return new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e){
            // 만료된 경우에는 refresh token을 확인하기 위해
            throw e;
        } catch (JwtException | IllegalArgumentException e) {
            throw e;
        }
    }

    public String createRefreshToken(Authentication authentication){
        Date now = new Date();
        Date validity = new Date(now.getTime() + refreshTokenValidityInMs);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }
}
```
토큰을 생성해주고 검증하는 등 토큰 관리 객체

### JwtTokenFilter
```Java
@Slf4j
public class JwtTokenFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * JWT를 검증하는 필터
     * HttpServletRequest 의 Authorization 헤더에서 JWT token을 찾고 그것이 맞는지 확인
     * UsernamePasswordAuthenticationFilter 앞에서 작동
     * (JwtTokenFilterConfigurer 참고)
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request, AUTHORIZATION_HEADER);

        try{
            if ( jwt != null && jwtTokenProvider.validateToken(jwt)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("set Authentication to security context for '{}', uri: {}", authentication.getName(), request.getRequestURI());
            }
        } catch(ExpiredJwtException e){
            request.setAttribute("exception", e);
            log.info("ExpiredJwtException : {}", e.getMessage());
        } catch(JwtException | IllegalArgumentException e){
            request.setAttribute("exception", e);
            log.info("jwtException : {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request, String header) {
        String bearerToken = request.getHeader(header);
        if (bearerToken != null && bearerToken.startsWith("Bearer-")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}

```
토큰을 처리하는 필터

### UserDetailsService

```Java
@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    /**
     * Spring-Security의 유저 인증 처리 과정중 유저객체를 만드는 과정
     * !! 보통 구글링시 UserDetails 클래스를 따로 만들어서 사용하지만 UserDetails 인터페이스를 구현한
     * User 라는 클래스를 시큐리티가 제공해줘서 굳이 만들어주지 않음
     * @param username : userId
     * @return UserDetails : (security에서 사용하는 유저 정보를 가진 객체)
     * @throws UsernameNotFoundException : userId로 유저를 찾지 못했을 경우 발생하는 에러
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByUserId(username)
                .orElseThrow(() -> new UsernameNotFoundException("userId : " + username + " was not found"));

        return createUserDetails(member);
    }

    private UserDetails createUserDetails(Member member) {
        // 권한 관리 테이블로 만든 깃
        // -> https://github.com/szerhusenBC/jwt-spring-security-demo/blob/master/src/main/java/org/zerhusen/security/model/User.java
        List<SimpleGrantedAuthority> grantedAuthorities = member.getRoleList().stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());

        return new User(member.getUserId(),
                member.getPw(),
                grantedAuthorities);
    }
}

```

### LoginService

```Java
@Service
@RequiredArgsConstructor
@Slf4j
public class LoginService {
    ... 생략
    
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
```
refresh token으로 access token 재발급 및 보안을 위해 refresh token 갱신

## Install

Redis와 H2 저장소 모두 in-memory 환경에서 작동하기 때문에 따로 설치할 것은 없다.

```
```

## Usage

```
./gradlew bootRun
```


## API
```text
localhost:8080/api/v1/signUp?id=test&pw=123
```
id : test , pw : 123 으로 회원가입
```text
localhost:8080/api/v1/signIn?id=test&pw=123
```
id : test , pw : 123 으로 로그인
```text
// Authorization 헤더에 accessToken 추가

localhost:8080/auth/test
```
인증 여부 테스트

```java

@RestController
@RequiredArgsConstructor
public class ApiController {
  private final LoginService loginService;

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

```
 토큰 만료시 재발급 요청 컨트롤러

## JWT 고찰
[개인 블로그](https://velog.io/@dyparkkk/series/securityjwtredis)
## 참고자료 
[https://github.com/murraco/spring-boot-jwt](https://github.com/murraco/spring-boot-jwt) <br>
[https://github.com/szerhusenBC/jwt-spring-security-demo](https://github.com/szerhusenBC/jwt-spring-security-demo) <br>
https://budnamu.tistory.com/entry/JWT <br>
https://kukekyakya.tistory.com/entry/Spring-boot-access-token-refresh-token-발급받기jwt <br>
https://jojoldu.tistory.com/297




## License

[MIT © dyparkkk](https://github.com/dyparkkk/jwt-spring-security-demo/blob/main/LICENSE)
