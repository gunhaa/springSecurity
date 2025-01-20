package springSecurity.JWT.OAuth2.OAuth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import springSecurity.JWT.OAuth2.dto.CustomOAuth2User;
import springSecurity.JWT.OAuth2.jwt.JwtUtil;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
                                    // 해당 클래스를 상속받고 특정 메소드()를 오버라이딩해서 기능을 대체시켜야한다.
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException{

        // OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*60L);

        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:8080/");

    }

    private Cookie createCookie(String key, String value) {
                                    // key, value
        // 키-값(key-value) 형태로 저장된 정보와 그 외의 기타 정보를 포함하는 데이터
        // dev tools application에서 확인 가능
        Cookie cookie = new Cookie(key, value);
        
        cookie.setMaxAge(60*60*60);
        // 쿠키가 유효한 경로를 설정
        cookie.setPath("/");
        // https환경에만 유효하도록
        // cookie.setSecure(true);
        // 자바스크립트에서 쿠키에 접근할 수 없게 만들어 보안을 강화
        cookie.setHttpOnly(true);
        // http헤더에 다음 형식으로 전송
        // Set-Cookie: your_cookie_key=your_token_value; Max-Age=216000; Path=/; HttpOnly; SameSite=Lax
        return cookie;
    }


}
