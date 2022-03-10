package com.example.jwtsprintsecuritydemo.redis;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash("RefreshToken")
public class RefreshToken {
    @Id
    private String id;
    private String token;

    @Builder
    public RefreshToken(String id, String token) {
        this.id = id;
        this.token = token;
    }

    public void reissue(String token) {
        this.token = token;
    }
}
