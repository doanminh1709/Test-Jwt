package com.example.practice_security.filters;

import com.example.practice_security.services.MyUserDetailsService;
import com.example.practice_security.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
// bộ lọc này có tác dụng chặn mọi yêu cầu chỉ một lần sau đó kiểm tra tiêu đề bên phải ,
//ta sẽ chặn mọi yêu cầu này chỉ một lần bằng cách mở rộng và
//tạo tên cho một bộ lọc chạy một lần cho mỗi yêu cầu
public class JwtRequestFilter extends OncePerRequestFilter {
    //Nhận trong chuỗi bộ lọc vì nó có tùy chọn chuyển cho bộ lọc tiếp theo trong
    // chuỗi bộ lọc hoặc thực sụ kết thúc yêu cầu ngay tại đó , tác dụng của nó là
    //    kiểm tra các yêu cầu đến cho JWT trong tiêu đề bên phải , nó xem xét
    //    các tiêu đề bên phải và xem liệu nó JWT đó có hợp lệ hay không , nếu nó
    //    tìm thấy khả năng đọc hợp lệ nó sẽ lấy chi tiết người dùng ra khỏi dịch vụ chỉ
    //    tiết người dùng và lưu nó vào bối cảnh bảo mật
    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUserName(jwt);
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(username);
            if (jwtUtil.validationToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
