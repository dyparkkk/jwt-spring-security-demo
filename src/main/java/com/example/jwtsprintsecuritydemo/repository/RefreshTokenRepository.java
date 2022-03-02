package com.example.jwtsprintsecuritydemo.repository;

import com.example.jwtsprintsecuritydemo.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    Optional<RefreshToken> findByUserId(String userId);
}
