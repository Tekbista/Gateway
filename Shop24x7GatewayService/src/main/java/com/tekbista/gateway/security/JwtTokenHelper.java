package com.tekbista.gateway.security;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.netty.handler.codec.http.HttpRequest;


@Component
public class JwtTokenHelper {

	
	@Value("${jwt.secret}")
	private  String SECRET;
	
	public Claims getClaims(final String token) {
		try {
			Claims body = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
			return body;
		}catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
		}
		
		return null;
	}
	
	
	
	
	public void validateToken(final String token) {
		try {
			
			Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
			
		} catch (SignatureException ex) {
			throw new SignatureException("Signature exception");
		}catch (MalformedJwtException ex) {
			throw new MalformedJwtException("Signature exception");
		}catch (ExpiredJwtException ex) {
			throw new ExpiredJwtException(null, null, "Token expired");
		}catch (UnsupportedJwtException ex) {
			throw new UnsupportedJwtException("Unsupported token");
		}catch (IllegalArgumentException ex) {
			throw new IllegalArgumentException("JWT claims string is empty.");
		}
	}
	
}
