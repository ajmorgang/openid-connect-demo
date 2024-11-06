package sample.config;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Example service to perform lookup of user info for customizing an {@code id_token}.
 */
@Service
public class OidcUserInfoService {

    private final UserInfoRepository userInfoRepository = new UserInfoRepository();

    public OidcUserInfo loadUser(String username) {
        return new OidcUserInfo(this.userInfoRepository.findByUsername(username));
    }

    static class UserInfoRepository {

        private final Map<String, Map<String, Object>> userInfo = new HashMap<>();

        public UserInfoRepository() {
            this.userInfo.put("user1", createUser());
        }

        public Map<String, Object> findByUsername(String username) {
            return this.userInfo.get(username);
        }

        private static Map<String, Object> createUser() {
            return OidcUserInfo.builder()
                    .subject("user1")
                    .name("First Last")
                    .givenName("First")
                    .familyName("Last")
                    .middleName("Middle")
                    .nickname("User")
                    .preferredUsername("user1")
                    .picture("https://example.com/" + "user1" + ".jpg")
                    .website("https://example.com")
                    .email("user1" + "@example.com")
                    .build()
                    .getClaims();
        }
    }

}
