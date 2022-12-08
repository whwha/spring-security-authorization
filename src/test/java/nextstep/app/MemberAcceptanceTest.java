package nextstep.app;

import io.restassured.RestAssured;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import nextstep.app.domain.Member;
import nextstep.app.infrastructure.InmemoryMemberRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class MemberAcceptanceTest extends AcceptanceTest {
    private static final Member TEST_MEMBER = InmemoryMemberRepository.ADMIN_MEMBER;

    @Test
    void get_members_after_form_login() {
        Map<String, String> params = new HashMap<>();
        params.put("username", TEST_MEMBER.getEmail());
        params.put("password", TEST_MEMBER.getPassword());

        ExtractableResponse<Response> loginResponse = RestAssured.given().log().all()
                .formParams(params)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .when()
                .post("/login")
                .then().log().all()
                .extract();

        ExtractableResponse<Response> memberResponse = RestAssured.given().log().all()
                .cookies(loginResponse.cookies())
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .when()
                .get("/members")
                .then().log().all()
                .extract();

        assertThat(memberResponse.statusCode()).isEqualTo(HttpStatus.OK.value());
        List<Member> members = memberResponse.jsonPath().getList(".", Member.class);
        assertThat(members.size()).isEqualTo(2);
    }

    @Test
    void get_members_before_form_login() {
        ExtractableResponse<Response> memberResponse = RestAssured.given().log().all()
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .when()
                .get("/members")
                .then().log().all()
                .extract();

        assertThat(memberResponse.statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }
}
