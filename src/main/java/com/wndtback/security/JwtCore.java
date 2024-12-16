package com.wndtback.security;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtCore {

    @Value("${wndtback.app.secret}")
    private String secret;

    @Value("${wndtback.app.lifetime}")
    private int lifetime;  // Длительность Access Token (например, 15 минут)

    @Value("${wndtback.app.refreshLifetime}")
    private int refreshLifetime;  // Длительность Refresh Token (например, 7 дней)

    // Генерация Access Token
    public String generateToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + lifetime))  // Срок действия Access Token
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    // Генерация Refresh Token
    public String generateRefreshToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshLifetime))  // Срок действия Refresh Token
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    // Извлечение имени пользователя из JWT токена
    public String getUserNameFromJwt(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Проверка срока действия токена (для Refresh Token)
    public boolean isRefreshTokenExpired(String token) {
        try {
            Date expiration = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody()
                    .getExpiration();
            return expiration.before(new Date());
        }
        catch (ExpiredJwtException e) {
            return true;
        }

    }
}
