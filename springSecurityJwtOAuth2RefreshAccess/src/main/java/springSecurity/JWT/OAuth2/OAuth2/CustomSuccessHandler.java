package springSecurity.JWT.OAuth2.OAuth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import springSecurity.JWT.OAuth2.dto.CustomOAuth2User;
import springSecurity.JWT.OAuth2.entity.RefreshEntity;
import springSecurity.JWT.OAuth2.jwt.JwtUtil;
import springSecurity.JWT.OAuth2.repository.RefreshRepository;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Component
                                    // 해당 클래스를 상속받고 특정 메소드()를 오버라이딩해서 기능을 대체시켜야한다.
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException{

        // OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        System.out.println("인증 성공시 역할 : " + role);
        /*
        로그인이 성공하면 기존에 단일 토큰만 발급했지만 보안을 위해서는 Access/Refresh에 해당하는 다중 토큰을 발급해야 한다.
        따라서 로그인이 성공한 이후 실행되는 onAuthenticationSuccess() 메소드
        또는 SimpleUrlAuthenticationSuccessHandler를 구현한 클래스에서 2개의 토큰을 발급한다.
        각각의 토큰은 생명주기와 사용처가 다르기 때문에 서로 다른 저장소에 발급한다.
        Access : 헤더에 발급 후 프론트에서 로컬 스토리지 저장
        Refresh : 쿠키에 발급        
        */

        // 변경 전
//        String token = jwtUtil.createJwt(username, role, 60*60*60L);
//
//        response.addCookie(createCookie("Authorization", token));
//        response.sendRedirect("http://localhost:8080/");

        // 변경 후
        //토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        addRefreshEntity(username, refresh, 86400000L);

        //응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());

        // 해당 자료들을 프론트에서 받아 세팅하면된다..
        System.out.println("customsuccesshandler 무사히 종료");
        response.sendRedirect("http://localhost:8080/");
    }

    private Cookie createCookie(String key, String value) {
                                    // key, value
        // 키-값(key-value) 형태로 저장된 정보와 그 외의 기타 정보를 포함하는 데이터
        // dev tools application에서 확인 가능
        Cookie cookie = new Cookie(key, value);
        
        cookie.setMaxAge(24*60*60);
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


    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

}
