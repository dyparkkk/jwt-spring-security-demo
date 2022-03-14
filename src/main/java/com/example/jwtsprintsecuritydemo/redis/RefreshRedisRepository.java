package com.example.jwtsprintsecuritydemo.redis;

import com.example.jwtsprintsecuritydemo.domain.RefreshToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshRedisRepository extends CrudRepository<RefreshRedisToken, String> {

}
