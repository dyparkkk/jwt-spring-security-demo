package com.example.jwtsprintsecuritydemo.redis;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash("RefreshToken")
public class RefreshRedisToken {
    @Id
    private String userId;
    private String token;

    @Builder
    private RefreshRedisToken(String userId, String token) {
        this.userId = userId;
        this.token = token;
    }

    static public RefreshRedisToken createToken(String userId, String token){
        return new RefreshRedisToken(userId, token);
    }

    public void reissue(String token) {
        this.token = token;
    }
}
