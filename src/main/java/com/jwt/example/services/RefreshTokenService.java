package com.jwt.example.services;

import com.jwt.example.entities.RefreshToken;
import com.jwt.example.entities.User;
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

        User user=userRepository.findByEmail(username).get();

        //if RT akready exists
        RefreshToken refreshToken1=user.getRefreshToken();

        if (refreshToken1==null) {
            refreshToken1 = RefreshToken.builder()
                    .refreshToken(UUID.randomUUID().toString())
                    .expiry(Instant.now().plusMillis(freshTime))
                    .user(user)
                    .build();
        }else{
            //if already exists ,extend validity
            refreshToken1.setExpiry(Instant.now().plusMillis(freshTime));
        }
        user.setRefreshToken(refreshToken1);
        refreshTokenRepository.save(refreshToken1);
        return refreshToken1;
    }
    public RefreshToken verifyRefreshToken(String refreshToken){
        //does token is real or not
       RefreshToken refreshToken1=refreshTokenRepository.findByRefreshToken(refreshToken).orElseThrow(()-> new RuntimeException("Token Doesn't exist"));

       //if real,expired or not
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
