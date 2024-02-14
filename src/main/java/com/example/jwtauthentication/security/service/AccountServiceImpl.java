package com.example.jwtauthentication.security.service;

import com.example.jwtauthentication.security.entities.AppRole;
import com.example.jwtauthentication.security.entities.AppUser;
import com.example.jwtauthentication.security.repositories.AppRoleRepository;
import com.example.jwtauthentication.security.repositories.AppUserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class AccountServiceImpl implements AccountService {
    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;
    @Override
    public AppUser addNewUser(AppUser appUser) {
        if(appUserRepository.findByUserName(appUser.getUserName())!=null) throw new RuntimeException("USER NAME ALREADY EXIST");
        //if(!(password.equals(confirmPassword))) throw new RuntimeException("password dosen't match");
        AppUser newUser= new AppUser();
        // String hashedPwd= passwordEncoder.encode(password);
        newUser.setUserName(appUser.getUserName());
        newUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        appUserRepository.save(newUser);
        return newUser;
    }

    @Override
    public AppRole addNewRole(String roleName) {
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        if(appRole!=null) throw new RuntimeException("ROLE ALREADY EXIST");
        AppRole newRole=new AppRole();
        newRole.setRoleName(roleName);
        appRoleRepository.save(newRole);
        return newRole;
    }


    @Override
    public void addRoleToUser(String userName, String roleName) {
        AppUser appUser=appUserRepository.findByUserName(userName);
        if(appUser==null) throw new RuntimeException("user not found");
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        if(appRole==null) throw new RuntimeException("role not found");
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public void removeRoleFromUser(String userName, String roleName) {
        AppUser appUser=appUserRepository.findByUserName(userName);
        if(appUser==null) throw new RuntimeException("user not found");
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        if(appRole==null) throw new RuntimeException("role not found");
        appUser.getAppRoles().remove(appRole);
    }

    @Override
    public AppUser LoadUserByUserName(String userName) {
        return appUserRepository.findByUserName(userName);

    }

    @Override
    public List<AppUser> userList() {
        return appUserRepository.findAll();
    }


}
