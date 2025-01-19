package springSecurity.JWT.yummi.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    // 버전마다 구현 방식이 많이 다르다 현재 버전은 0.12.3
    public JWTUtil(@Value("${spring.jwt.secret}") String secret){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token){
               //jwt parser 사용, 검증 진행(secretkey 이용), claim를 확인하고, payload에서 데이터를 가져온다. 획득할 데이터는 username이며, 가지고올 데이터 타입은 String이다.
               // parseSignedClaims :  JWT 토큰을 받아서 그 안에 있는 정보를 추출하고, 해당 토큰이 서명된 대로 변조되지 않았는지 검증하는 과정에서 사용
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs){
        // JWT 빌더를 사용해서 토큰을 생성한다.
        return Jwts.builder()
                // claim메서드를 통해 key를 넣어줄 수 있다.
                .claim("username", username)
                .claim("role", role)
                // 토큰 발행 시간
                .issuedAt(new Date(System.currentTimeMillis()))
                // 토큰 만료 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                // 시그니처 암호화 만들기 진행
                .signWith(secretKey)
                // 토큰을 compact 한다.
                .compact();
    }

}
