package com.cn.hotel.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.cn.hotel.dto.UserRequest;
import com.cn.hotel.model.Role;
import com.cn.hotel.model.Users;
import com.cn.hotel.repository.UserRepository;

@Service
public class UserService {


	private final UserRepository userRepository;

	public UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	public List<Users> getAllUsers() {
		return userRepository.findAll();
	}

	public void createUser(UserRequest userRequest) {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		String encodedPassword = bCryptPasswordEncoder.encode(userRequest.getPassword());

		Users user = new Users();
		user.setUsername(userRequest.getUsername());
		//user.setPassword(userRequest.getPassword());
		user.setPassword(encodedPassword);
		Role role = new Role();
		Set<Role> roles = new HashSet<>();
		if(userRequest.getUserType() != null) {
			if (userRequest.getUserType().equalsIgnoreCase("ADMIN")) {
				role.setRoleName("ROLE_ADMIN");
				roles.add(role);
				user.setRoles(roles);
			}
			else if (userRequest.getUserType().equalsIgnoreCase("NORMAL")) {
				role.setRoleName("ROLE_NORMAL");
				roles.add(role);
				user.setRoles(roles);
			} else {
				role.setRoleName("ROLE_NORMAL");
				roles.add(role);
				user.setRoles(roles);
			}
		}
		else {
			role.setRoleName("ROLE_NORMAL");
			roles.add(role);
			user.setRoles(roles);
		}

		userRepository.save(user);
	}



}
