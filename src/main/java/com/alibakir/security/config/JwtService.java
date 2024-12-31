package com.alibakir.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "a3e3af28b0174909f712a76fe88263b211bc8f26d7fe7f2eb1ea0938494fb3fb";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResulver){

        // Claims nesnesi içindeki belirli bir alanı (örneğin expiration)
        // çıkarıp döndürür.
        final Claims claims= extractAllClaims(token);
        return claimsResulver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        // JWT token'dan kullanıcı adını çıkarıyoruz
        final String username=extractUsername(token);

        // Kullanıcı adı, UserDetails içindeki kullanıcı adıyla eşleşiyor mu
        // ve token'ın süresi dolmamış mı kontrol ediyoruz
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){

        // Token içindeki expiration (son kullanma) tarihini alır ve
        // şu anki tarih ile karşılaştırır.
        // Eğer süresi dolmuşsa true döner.
        return extractExpration(token).before(new Date());
    }

    private Date extractExpration(String token){

        // Token'dan expiration (son kullanma tarihi) alanını çıkarır
        // Claims::getExpiration, expiration alanını çıkarmak için kullanılır
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {

        // JWT token'ını ayrıştırarak tüm claim'leri çıkarır
        // Ayrıştırma sırasında SECRET_KEY ile doğrulama yapılır

        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // Doğrulama için gizli anahtar kullanılır
                .build()
                .parseClaimsJws(token) // Token'ın geçerliliğini kontrol eder
                .getBody(); // Claims (token içeriği) döner
    }

    private Key getSignInKey(){
    byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
    }
}
