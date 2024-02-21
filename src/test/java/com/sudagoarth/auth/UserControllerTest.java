package com.sudagoarth.auth;

import com.sudagoarth.auth.entity.UserInfo;
import com.sudagoarth.auth.repository.UserInfoRepository;
import com.sudagoarth.auth.service.UserInfoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.Rollback;

import static org.assertj.core.api.Assertions.assertThat;


@DataJpaTest(showSql = false)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Rollback(false)
public class UserControllerTest {

        @Autowired
        private UserInfoRepository userInfoRepository;

        @Test
        public void testWelcome() {
        }

        @Test
        public void testAddNewUser() {
            UserInfo userInfo = new UserInfo();
            userInfo.setName("test");
            userInfo.setEmail("test@test.com");
            userInfo.setPassword("test");
            userInfo.setRoles("ROLE_USER");
            userInfoRepository.save(userInfo);
            assertThat( userInfoRepository.findByEmail("test@test.com").isPresent()).isTrue();
        }

        @Test
        public void testUserProfile() {

        }

        @Test
        public void testAdminProfile() {

        }

        @Test
        public void testAuthenticateAndGetToken() {

        }
}
