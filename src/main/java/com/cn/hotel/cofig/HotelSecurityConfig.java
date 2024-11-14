package com.cn.hotel.cofig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class HotelSecurityConfig {
	
	@Autowired
	UserDetailsService userDetailsService;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.csrf().disable()
			.authorizeHttpRequests()
			.requestMatchers("/user/register").permitAll()
			//.antMatchers("/hotel/create").hasRole("ADMIN")
			//.requestMatchers("/hotel/create").hasRole("ADMIN")
			//.requestMatchers("/hotel/**").hasRole("ADMIN") //for any api request
			.anyRequest()
			.authenticated()
			.and()
			.rememberMe().userDetailsService(userDetailsService)
			.and()
			.formLogin()	//for form login authentication
			//.httpBasic(); // for Basic authentication
			.loginPage("/login").permitAll()
			.and()
			.logout().deleteCookies("remember-me");

		return http.build();

	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/*

	@Bean
	public UserDetailsService users() {

		UserDetails user1 = User.builder()
				.username("tony")
				.password(passwordEncoder().encode("password"))
				.roles("NORMAL")
				.build();

		UserDetails user2 = User.builder()
				.username("steve")
				.password(passwordEncoder().encode("nopassword"))
				.roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user1, user2);

	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	 */

}
