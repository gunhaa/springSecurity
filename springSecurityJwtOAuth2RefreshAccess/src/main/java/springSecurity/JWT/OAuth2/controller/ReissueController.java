package springSecurity.JWT.OAuth2.controller;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import springSecurity.JWT.OAuth2.entity.RefreshEntity;
import springSecurity.JWT.OAuth2.jwt.JwtUtil;
import springSecurity.JWT.OAuth2.repository.RefreshRepository;

import java.util.Date;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class ReissueController {

    private final JwtUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response){

        // 서비스 단에 로직을 넣어 분리시키는 방향이 좋다
        
        //get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        if(cookies!=null){
            for(Cookie cookie : cookies){
                if(cookie.getName().equals("refresh")){
                    refresh=cookie.getValue();
                }
            }
        }

        if(refresh==null){
            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // expired check
        try{
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e){
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        String category = jwtUtil.getCategory(refresh);
        // 토큰 refresh인지 확인(발급 시 페이로드에 명시)
        if(!category.equals("refresh")){
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }


        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {

            //response body
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // jwt를 새로 만든다
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        // Rotate 되기 이전의 토큰을 가지고 서버측으로 가도 인증이 되기 때문에
        // 서버측에서 발급했던 Refresh들을 기억한 뒤 블랙리스트 처리를 진행하는 로직을 작성해야 한다.
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        //Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        // TTL 설정을 통해 자동으로 Refresh 토큰이 삭제되면 무방하지만
        // 계속해서 토큰이 쌓일 경우 용량 문제가 발생할 수 있다.
        // 따라서 스케줄 작업을 통해 만료시간이 지난 토큰은 주기적으로 삭제하는 것을 추가 구현해야한다.
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        // 결과에 담기
        response.addCookie(createCookie("refresh", newRefresh));
        response.setHeader("access", newAccess);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie createCookie(String key, String value) {
        // key, value
        // 키-값(key-value) 형태로 저장된 정보와 그 외의 기타 정보를 포함하는 데이터
        // dev tools application에서 확인 가능
        Cookie cookie = new Cookie(key, value);

        cookie.setMaxAge(24*60*60);
        // 쿠키가 유효한 경로를 설정
//        cookie.setPath("/");
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
