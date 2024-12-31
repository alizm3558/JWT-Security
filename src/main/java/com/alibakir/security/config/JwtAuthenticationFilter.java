package com.alibakir.security.config;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;



    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return; // return eklenmeli, aksi takdirde devam eder.
        }

        jwt = authHeader.substring(7);

        try {
            // JWT içeriğinden kullanıcı adını çıkar
            userEmail = jwtService.extractUsername(jwt);

            // Eğer kullanıcı e-posta adresi mevcutsa ve kullanıcı şu anda kimlik doğrulanmamışsa (oturum açmamışsa)
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Kullanıcı bilgilerini e-posta adresine göre yükler (örneğin, kullanıcı adı, roller gibi)
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // Eğer JWT token geçerli ise (doğrulama süresi, imza, kullanıcı bilgileri gibi kontroller yapılır)
                if (jwtService.isTokenValid(jwt, userDetails)) {

                    // Yeni bir UsernamePasswordAuthenticationToken nesnesi oluşturulur.
                    // Bu nesne, kullanıcının kimliğini ve yetkilerini temsil eder.
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, // Kimlik doğrulama için kullanıcı bilgileri
                            null, // Şifre gerekmediği için null olarak bırakılır
                            userDetails.getAuthorities() // Kullanıcının sahip olduğu yetki ve roller
                    );

                    // Kimlik doğrulama detayları talebe özgü bilgilerle güncellenir (IP adresi, oturum bilgileri gibi)
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Kullanıcının kimlik doğrulama bilgisi güvenlik bağlamına (SecurityContext) atanır
                    // Böylece kullanıcı, uygulamanın geri kalanında kimlik doğrulanmış olarak kabul edilir.
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }


        } catch (ExpiredJwtException ex) {
            // Süresi dolmuş token durumu için özel yanıt oluştur
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token has expired. Please login again.");
            return; // Yanıt gönderildikten sonra filtre zincirine devam edilmez.
        } catch (Exception ex) {
            // Diğer hatalar için loglama yapılabilir veya farklı yanıt döndürülebilir
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid token.");
            return;
        }

        filterChain.doFilter(request, response);
    }

}
