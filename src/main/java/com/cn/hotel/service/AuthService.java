package com.cn.hotel.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.cn.hotel.dto.JwtRequest;
import com.cn.hotel.dto.JwtResponse;
import com.cn.hotel.jwt.JwtAuthenticationHelper;

@Service
public class AuthService {

	@Autowired
	AuthenticationManager manager;
	
	@Autowired
	JwtAuthenticationHelper jwtHelper;
	
	@Autowired
	UserDetailsService userDetailsService;
	
	public JwtResponse login(JwtRequest jwtRequest) {
		//Authenticate with authentication manager
		this.doAuthenticate(jwtRequest.getUsername(), jwtRequest.getPassword());
		
		UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
		String token = jwtHelper.generateToken(userDetails);
		JwtResponse jwtResponse = JwtResponse.builder().jwtToken(token).build();
		return jwtResponse;
	}

	private void doAuthenticate(String username, String password) {
		
		//to create authentication object to pass to authenticate method
		UsernamePasswordAuthenticationToken authenticationToken = 
				new UsernamePasswordAuthenticationToken(username, password);
		try {
			manager.authenticate(authenticationToken);
		} 
		catch (BadCredentialsException e) {
			throw new BadCredentialsException("Invalid Username or Password");
		}
		
		
	}
	
	
	
	

}
