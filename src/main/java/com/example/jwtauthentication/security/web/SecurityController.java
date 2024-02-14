package com.example.jwtauthentication.security.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.jwtauthentication.security.RoleUserForm;
import com.example.jwtauthentication.security.entities.AppRole;
import com.example.jwtauthentication.security.entities.AppUser;
import com.example.jwtauthentication.security.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
public class SecurityController {
    private AccountService accountService;

    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> userList(){
        return accountService.userList();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody String roleName){
        return accountService.addNewRole(roleName);
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUserName(), roleUserForm.getRoleName());
    }
    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken=request.getHeader("Authorization");
        if(authToken!=null && authToken.startsWith("Bearer ")){
            try {
                String jwt = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mysecret123");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.LoadUserByUserName(username);
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 5 * 6 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", appUser.getAppRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
                Map<String, String> idToken = new HashMap<>();
                idToken.put("accessToke", jwtAccessToken);
                idToken.put("refreshToken", jwt);
                response.setContentType("application/json");
                response.setHeader("Authorization", jwtAccessToken);
                new ObjectMapper().writeValue(response.getOutputStream(), idToken);
            }
            catch (Exception e){
                response.setHeader("error-message",e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        else {
            throw new RemoteException("Refresh token Required");
        }
    }
}

