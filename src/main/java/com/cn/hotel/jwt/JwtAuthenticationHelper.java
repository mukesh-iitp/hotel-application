package com.cn.hotel.jwt;

import java.security.KeyStore.SecretKeyEntry;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JwtAuthenticationHelper {
	
	private String secret = "";
	
	public String getUsernameFromToken(String token) {
		
		Claims claims = getClaimsFromToken(token);
		
		return claims.SUBJECT;
		
	}
	
	public Boolean isTokenExpired(String token) {
		
		Claims claims = getClaimsFromToken(token);
		Date expDate = claims.getExpiration();
		
		return expDate.before(new Date());
		
	}
	
	public Claims getClaimsFromToken(String token) {
		
		Claims claims = Jwts.parserBuilder().setSigningKey(secret.getBytes())
				.build().parseClaimsJws(token).getBody();
		
		return claims;
	}

}
