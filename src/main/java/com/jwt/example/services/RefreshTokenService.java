package com.jwt.example.services;

import com.jwt.example.entities.RefreshToken;
import com.jwt.example.repositories.RefreshTokenRepository;
import com.jwt.example.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    public long freshTime=5*60*60*1000;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public RefreshToken createRefreshToken(String username){
        RefreshToken refreshToken= RefreshToken.builder()
                .refreshToken(UUID.randomUUID().toString())
                .expiry(Instant.now().plusMillis(freshTime))
                .user(userRepository.findByEmail(username).get())
                .build();

        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }
    public RefreshToken verifyRefreshToken(String refreshToken){
       RefreshToken refreshToken1=refreshTokenRepository.findById(refreshToken).orElseThrow(()-> new RuntimeException("Token Doesn't exist"));
        if(refreshToken1.getExpiry().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(refreshToken1);
            throw new RuntimeException("Token Expired");
        }
//        else{
//            return true;
//        } //or
        return refreshToken1;
    }
}
