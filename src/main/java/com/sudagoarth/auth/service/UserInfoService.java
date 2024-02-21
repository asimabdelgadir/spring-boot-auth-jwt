package com.sudagoarth.auth.service;

import com.sudagoarth.auth.UserInfoDetails;
import com.sudagoarth.auth.entity.UserInfo;
import com.sudagoarth.auth.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserInfoService implements UserDetailsService {

    @Autowired
    private UserInfoRepository repository;

    @Autowired
    private PasswordEncoder encoder;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<UserInfo> userDetail = repository.findByEmail(email);

        // Converting userDetail to UserDetails
        return userDetail.map(UserInfoDetails::new).orElseThrow(() -> new UsernameNotFoundException("User not found " + email));
    }

    public boolean addUser(UserInfo userInfo) {
        userInfo.setPassword(encoder.encode(userInfo.getPassword()));
        if (repository.findByEmail(userInfo.getEmail()).isPresent()) {
            return false;
        } else {
            repository.save(userInfo);
            return true;
        }
    }


    public UserInfo getUser(String username) {
        return repository.findByEmail(username).orElse(null);
    }
    public UserInfo getUserWithoutPassword(String username) {
        UserInfo user = repository.findByEmail(username).orElse(null);
        if (user != null) {
            return new UserInfo(user.getId(), user.getName(), user.getEmail(), user.getRoles());
        }
        return null;
    }
    public Iterable<UserInfo> getAllUsers() {
        return repository.findAll();
    }

    public boolean deleteUser(String username) {
        if (repository.findByEmail(username).isPresent()) {
            repository.deleteByEmail(username);
            return true;
        } else {
            return false;
        }
    }

    public boolean updateUser(String username, UserInfo userInfo) {
        if (repository.findByEmail(username).isPresent()) {
            userInfo.setPassword(encoder.encode(userInfo.getPassword()));
            repository.save(userInfo);
            return true;
        } else {
            return false;
        }
    }


}