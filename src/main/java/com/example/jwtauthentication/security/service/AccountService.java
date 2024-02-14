package com.example.jwtauthentication.security.service;

import com.example.jwtauthentication.security.entities.AppRole;
import com.example.jwtauthentication.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(String roleName);
    void addRoleToUser(String userName, String roleName);
    void removeRoleFromUser (String userName, String roleName);
    AppUser LoadUserByUserName(String userName);
    List<AppUser> userList();

}
