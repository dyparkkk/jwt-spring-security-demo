package com.example.jwtsprintsecuritydemo.redis;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class RefreshRedisRepositoryTest {

    @Autowired
    private RefreshRedisRepository refreshRedisRepository;

    @AfterEach
    public void tearDown() throws Exception {
        refreshRedisRepository.deleteAll();
    }

    @Test
    void 기본_등록_조회기능() {
        String id = "dyparkkk";
        RefreshToken token = RefreshToken.builder()
                .id(id)
                .token("token")
                .build();

        // when
        refreshRedisRepository.save(token);

        RefreshToken findToken = refreshRedisRepository.findById(id).get();
        assertThat(findToken.getToken()).isEqualTo("token");
    }

    @Test
    void 수정기능() {
        String id = "dyparkkk";
        refreshRedisRepository.save(RefreshToken.builder()
               .id(id)
               .token("token")
               .build());

        //when
        RefreshToken findToken = refreshRedisRepository.findById(id).get();
        findToken.reissue("new_token");
        refreshRedisRepository.save(findToken);

        //then
        RefreshToken refreshToken = refreshRedisRepository.findById(id).get();
        assertThat(refreshToken.getToken()).isEqualTo("new_token");
    }

}