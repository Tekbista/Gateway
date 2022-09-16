package com.tekbista.gateway.security;

import java.util.List;
import java.util.function.Predicate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GatewayFilter{

	@Autowired
	private JwtTokenHelper jwtTokenHelper;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		
		ServerHttpRequest request = exchange.getRequest();
		
		final List<String> apiEndpoints = List.of(
				"api/v1/auth/register", 
				"/api/v1/auth/login",
				"/api/v1/auth/forgetPassword"
			);
		
		Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream().noneMatch(uri -> r.getURI().getPath().contains(uri));
		
		if(isApiSecured.test(request)) {
			
			if(!request.getHeaders().containsKey("Authorization")) {
				ServerHttpResponse response = exchange.getResponse();
				response.setStatusCode(HttpStatus.UNAUTHORIZED);
				return response.setComplete();
			}
			
			final String tokenHeader = request.getHeaders().getOrEmpty("Authorization").get(0);
			final String token = tokenHeader.substring(7);
			
			try {
				jwtTokenHelper.validateToken(token);
			}catch (Exception ex) {
				ServerHttpResponse response = exchange.getResponse();
				response.setStatusCode(HttpStatus.BAD_REQUEST);
				
				return response.setComplete();
			}
			
			Claims claims = jwtTokenHelper.getClaims(token);
			exchange.getRequest().mutate().header("id", String.valueOf(claims.get("id"))).build();
		}
		
		return chain.filter(exchange);
	}

	
	
}
