package springSecurity.JWT.OAuth2.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import springSecurity.JWT.OAuth2.dto.CustomOAuth2User;
import springSecurity.JWT.OAuth2.dto.UserDTO;

import java.io.IOException;

// springSecuirity filterchain에 담긴 jwt를 검증하기위해 커스텀 필터가 필요하다.
// 해당 필터를 통해 요청 쿠키에 JWT가 존재하는 경우 JWT를 검증하고 강제로SecurityContextHolder에 세션을 생성한다.
// 이 세션은 STATLESS 상태로 관리되기 때문에 해당 요청이 끝나면 소멸 된다.
                            // 요청에 대해 한번만 요청되면 될때 사용

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        System.out.println("cookies = " + cookies);

        if(cookies!=null){
            for(Cookie cookie : cookies){
//            System.out.println("cookie.getName() = " + cookie.getName());

                if(cookie.getName().equals("Authorization")){
                    authorization = cookie.getValue();
                }
            }
        }


        // Authorization 헤더 검증
        if(authorization == null){
            System.out.println("token null");
            filterChain.doFilter(request,response);
            // 조건이 해당되면 메소드 종료
            return;
        }

        // 토큰
        String token = authorization;

        // 토큰 소멸 시간 검증
        if(jwtUtil.isExpired(token)){
            System.out.println("token Expired");
            filterChain.doFilter(request, response);
            return ;
        }

        // 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);

        // UserDetails에 정보 객체 담기
        // oauth2user 객체가 authentication을 만들떄 필요하기 때문에 해당 객체가 필요하다
        // userentity사용 안하고 dto로 만들어서 사용한건 불필요한건 노출 안시키기 위해 그런것이다.
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        // 스프링 시큐리티 인증 토큰 생성
        // 파라미터 1 : 인증된 사용자 정보가 담긴 객체를 넣는다
        // 파라미터 2 : 비밀번호를 넣지만, OAuth2에선 필요가없다
        // 파라미터 3 : 어떤 권한을 가지고있는지
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        // 세션에 사용자 등록
        // 인증 토큰을 SecurityContext에 설정하여, 애플리케이션 내에서 인증된 사용자로 인식될 수 있게 함
        // SecurityContextHolder는 현재 스레드에서 사용자의 인증 정보를 저장하는 SecurityContext를 관리하는 클래스
        // SecurityContext는 현재 인증된 사용자의 정보와 그 상태를 관리한다. 이 클래스에 인증 정보를 설정하면, 이후 요청에서 인증된 사용자로 인식
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);
    }

}
