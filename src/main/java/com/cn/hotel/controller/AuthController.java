package com.cn.hotel.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cn.hotel.dto.AuthResponse;
import com.cn.hotel.dto.JwtRequest;
import com.cn.hotel.dto.JwtResponse;
import com.cn.hotel.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	AuthService authService;
	
	//For implementation of jwt authentication
	@PostMapping("/login")
	public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest jwtRequest) {
		return new ResponseEntity<>(authService.login(jwtRequest), HttpStatus.OK);
	}
	
	
	@GetMapping("/login")
	public ResponseEntity<AuthResponse> login(
				@RegisteredOAuth2AuthorizedClient("okta")
				OAuth2AuthorizedClient oAuth2AuthorizedClient,
				@AuthenticationPrincipal OidcUser user){
		
		AuthResponse authResponse = new AuthResponse();
		
		authResponse.setUserID(user.getEmail());
		authResponse.setAccessToken(oAuth2AuthorizedClient.getAccessToken().getTokenValue());
		authResponse.setExpireAt(oAuth2AuthorizedClient.getAccessToken().getExpiresAt().getEpochSecond());
		
		List<String> authorities =  user.getAuthorities().stream()
			.map(grantedAuthority -> {return grantedAuthority.getAuthority();})
			.collect(Collectors.toList());
		
		authResponse.setAuthorities(authorities);
		
		return new ResponseEntity<>(authResponse, HttpStatus.OK);
	}
	

}
