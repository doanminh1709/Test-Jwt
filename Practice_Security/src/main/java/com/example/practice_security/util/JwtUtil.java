package com.example.practice_security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private final String SECRET_KEY = "DoanMinh17092002";
    private final long validityInMilliseconds = 3600000; // 1h

    //Trích xuất ra thông tin người dùng từ token
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Trích xuất ra thời điểm đăng nhập để lấy thời gian kiểm tra
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    //Xác nhận quyền sở hữu lấy mã thông báo và sau đó sử dụng trình giải quyềt yêu cầu gửi lên ,
    //để tìm ra những yêu cầu này đúng
    // Nó sẽ sử dụng phương pháp trích xuất này để lấy thông tin từ một mã thông báo hiện có.


    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Tạo ra một Jwt dựa trên chi tiết người dùng đăng nhập
    //Xác nhận quyền sở hữu và lấy tên người dùng và sau đó tạo ra mã thông báo từ nó
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    //Hàm tạo ra token
    // setClaims : Thiết lập các yêu cầu xác nhận mà chúng ta đã chuyển vào ngay bây giờ
    // setObject : Xác lập chủ thể là người đang thực thành công
    // signWith : xác nhận thuộc toán mà key để tạo ra token
    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    //Phương thức kiểm tra mã thông báo có hợp lệ lấy tên người dùng bằng cách sử dụng
    //tên người dùng và sau đó trích xuất xem nó có giống với thông tin người dùng hay không
    // và kiểm tra xem mã này hết hạn hay chưa
    public Boolean validationToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
