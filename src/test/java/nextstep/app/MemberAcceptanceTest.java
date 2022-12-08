package nextstep.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.restassured.RestAssured;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

public class MemberAcceptanceTest extends AcceptanceTest {
    private static final Member ADMIN = InmemoryMemberRepository.ADMIN_MEMBER;
    private static final Member USER = InmemoryMemberRepository.USER_MEMBER;

    @DisplayName("인가된 사용자는 200 응답을 받고 members 조회가 가능하다.")
    @Test
    void get_members_after_form_login_admin() {
        final ExtractableResponse<Response> loginResponse = 로그인(ADMIN.getEmail(), ADMIN.getPassword());

        ExtractableResponse<Response> memberResponse = RestAssured.given().log().all()
            .cookies(loginResponse.cookies())
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .when()
            .get("/members")
            .then().log().all()
            .extract();

        assertAll(
            () -> assertThat(memberResponse.statusCode()).isEqualTo(HttpStatus.OK.value()),
            () -> {
                List<Member> members = memberResponse.jsonPath().getList(".", Member.class);
                assertThat(members.size()).isEqualTo(2);
            }
        );
    }

    @DisplayName("인가되지 않은 사용자는 403 응답을 받는다.")
    @Test
    void get_members_after_form_login_user() {
        final ExtractableResponse<Response> loginResponse = 로그인(USER.getEmail(), USER.getPassword());

        ExtractableResponse<Response> memberResponse = RestAssured.given().log().all()
            .cookies(loginResponse.cookies())
            .contentType(MediaType.APPLICATION_JSON_VALUE)
            .when()
            .get("/members")
            .then().log().all()
            .extract();

        assertThat(memberResponse.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    private ExtractableResponse<Response> 로그인(String username, String password) {
        return RestAssured.given().log().all()
            .formParams(Map.of(
                "username", username,
                "password", password
            ))
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .when()
            .post("/login")
            .then().log().all()
            .extract();
    }
}
