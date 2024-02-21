package com.sudagoarth.auth.controller;

import com.sudagoarth.auth.entity.ApiResponse;
import com.sudagoarth.auth.entity.ApiResponseWithToken;
import com.sudagoarth.auth.entity.AuthRequest;
import com.sudagoarth.auth.JwtService;
import com.sudagoarth.auth.entity.UserInfo;
import com.sudagoarth.auth.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserInfoService service;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public UserController(UserInfoService service, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.service = service;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/welcome")
    public ApiResponse welcome() {
        return new ApiResponse(true, "Welcome to the API", null);
    }

    @PostMapping("/add-new-user")
    public ApiResponse addNewUser(@RequestBody UserInfo userInfo) {
        if (service.addUser(userInfo)) {
            return new ApiResponse(true, "User added successfully", null);
        } else {
            return new ApiResponse(false, "User already exists", null);
        }
    }

    @GetMapping("/user/user-profile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ApiResponse userProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return new ApiResponse(true, "Welcome to User Profile", service.getUserWithoutPassword(username));
    }

    @GetMapping("/admin/admin-profile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse adminProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return new ApiResponse(true, "Welcome to Admin Profile", service.getUserWithoutPassword(username));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest.password()));
        if (authentication.isAuthenticated()) {
            String username = authentication.getName();
            UserInfo user = service.getUserWithoutPassword(username);
            String token = jwtService.generateToken(username);
            return ResponseEntity.ok( new ApiResponseWithToken(true, "Token generated successfully", user, token));
//            return new ApiResponseWithToken(true, "Token generated successfully", user, token);
        } else {
            return ResponseEntity.ok(new ApiResponse(false, "Invalid username or password", null));
        }
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public UserInfo getUser(@PathVariable String username) {
        return service.getUser(username);
    }

    @GetMapping("/user/all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Iterable<UserInfo> getAllUsers() {
        return service.getAllUsers();
    }

    @DeleteMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse deleteUser(@PathVariable String username) {
        if (service.deleteUser(username)) {
            return new ApiResponse(true, "User deleted successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @PutMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse updateUser(@PathVariable String username, @RequestBody UserInfo userInfo) {
        if (service.updateUser(username, userInfo)) {
            return new ApiResponse(true, "User updated successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @GetMapping("/user/{username}/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse getUserRoles(@PathVariable String username) {
        UserInfo user = service.getUser(username);
        if (user != null) {
            return new ApiResponse(true, "Roles of user " + username, user.getRoles());
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @PutMapping("/user/{username}/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse updateUserRoles(@PathVariable String username, @RequestBody UserInfo userInfo) {
        if (service.updateUser(username, userInfo)) {
            return new ApiResponse(true, "Roles of user " + username + " updated successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @GetMapping("/user/{username}/roles/{role}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse getUserRole(@PathVariable String username, @PathVariable String role) {
        UserInfo user = service.getUser(username);
        if (user != null) {
            return new ApiResponse(true, "Role of user " + username, user.getRoles());
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

}