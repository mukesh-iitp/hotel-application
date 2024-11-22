package com.cn.hotel.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cn.hotel.model.Users;

public interface UserRepository extends JpaRepository<Users, Long>{

	Optional<Users> findByUsername(String username);

}
