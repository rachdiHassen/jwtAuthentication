package com.example.jwtauthentication.security.repositories;


import com.example.jwtauthentication.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,String> {
    AppRole findByRoleName(String roleName);
}