package nextstep.app;

import nextstep.security.authentication.Authentication;
import nextstep.security.context.SecurityContextHolder;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InMemoryMemberRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class LoginTest {
    private static final Member TEST_MEMBER = InMemoryMemberRepository.ADMIN_MEMBER;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void login_success() throws Exception {
        ResultActions loginResponse = requestLoginWith(TEST_MEMBER.getEmail(), TEST_MEMBER.getPassword());
        loginResponse.andExpect(status().isOk());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    void login_fail_with_no_user() throws Exception {
        ResultActions response = requestLoginWith("none", "none");

        response.andExpect(status().isUnauthorized());
    }

    @Test
    void login_fail_with_invalid_password() throws Exception {
        ResultActions response = requestLoginWith(TEST_MEMBER.getEmail(), "invalid");

        response.andExpect(status().isUnauthorized());
    }

    private ResultActions requestLoginWith(String username, String password) throws Exception {
        return mockMvc.perform(post("/login")
                .param("username", username)
                .param("password", password)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        );
    }
}
