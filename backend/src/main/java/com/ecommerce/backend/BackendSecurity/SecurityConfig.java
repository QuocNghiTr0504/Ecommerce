package com.ecommerce.backend.BackendSecurity;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.http.HttpMethod;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final JwtRequestFilter jwtRequestFilter;

    public SecurityConfig(UserDetailsService userDetailsService, JwtRequestFilter jwtRequestFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtRequestFilter = jwtRequestFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .cors()
                .and()
                .authorizeRequests()

                // chỉ admin mới có quyền truy cập api
                .antMatchers(HttpMethod.POST, "/api/videos/**").permitAll()
                .antMatchers(HttpMethod.PUT, "/api/videos/**").permitAll()
                .antMatchers(HttpMethod.PATCH, "/api/videos/**").permitAll()
                .antMatchers(HttpMethod.DELETE, "/api/videos/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/videos/**").permitAll()
                // .antMatchers("/api/videos/delete/{id}").permitAll()
                // .antMatchers("/api/videos/update/{id}").permitAll()
                // .antMatchers("/api/videos/upload-video").permitAll()

                .antMatchers(HttpMethod.POST, "/api/blogs/**").hasRole("ADMIN") // Chỉ ADMIN mới có thể tạo
                .antMatchers(HttpMethod.PUT, "/api/blogs/**").hasRole("ADMIN") // Chỉ ADMIN mới có thể cập nhật
                .antMatchers(HttpMethod.PATCH, "/api/blogs/**").hasRole("ADMIN") // Chỉ ADMIN mới có thể cập nhật
                .antMatchers(HttpMethod.DELETE, "/api/blogs/**").hasRole("ADMIN") // Chỉ ADMIN mới có thể xóa
                .antMatchers(HttpMethod.GET, "/api/blogs/**").permitAll() // Mọi người đều có thể đọc
                // .antMatchers("/api/blogs/create").permitAll()
                // .antMatchers("/api/blogs/update/{id}").permitAll()
                // .antMatchers("/api/blogs/all").permitAll()
                // .antMatchers("/api/blogs/delete/{id}").permitAll()

                .antMatchers(HttpMethod.POST, "/api/categorys/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/categorys/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PATCH, "/api/categorys/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/categorys/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/categorys/**").permitAll()

                .antMatchers(HttpMethod.PATCH, "/api/accounts/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/accounts/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/accounts/**").permitAll()
                .antMatchers(HttpMethod.PUT, "/api/accounts/**").permitAll()
                .antMatchers(HttpMethod.POST, "/api/accounts/**").permitAll()
                // .antMatchers("/api/accounts/update/{id}").permitAll()
                // .antMatchers("/api/accounts/create").permitAll()

                .antMatchers(HttpMethod.POST, "/api/feedbacks/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/feedbacks/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PATCH, "/api/feedbacks/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/feedbacks/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/feedbacks/**").permitAll()
                // .antMatchers("/api/feedbacks/create").permitAll()
                // .antMatchers("/api/feedbacks/update/{id}").permitAll()
                // .antMatchers("/api/feedbacks/delete/{id}").permitAll()
                // .antMatchers("/api/feedbacks/all").permitAll()

                .antMatchers(HttpMethod.POST, "/api/roles/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/roles/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PATCH, "/api/roles/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/roles/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/roles/**").permitAll()
                // .antMatchers("/api/roles/all").permitAll()
                // .antMatchers("/api/roles/create").permitAll()

                .antMatchers(HttpMethod.POST, "/api/faqs/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/faqs/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PATCH, "/api/faqs/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/faqs/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/faqs/**").permitAll()

                .antMatchers(HttpMethod.PUT, "/api/contacts/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.PATCH, "/api/contacts/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/contacts/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/api/contacts/**").permitAll()
                .antMatchers(HttpMethod.POST, "/api/contacts/**").permitAll()
                // chỉ admin mới có quyền truy cập api

                .antMatchers(HttpMethod.POST, "/api/watch-history/**").permitAll()
                .antMatchers(HttpMethod.GET, "/api/watch-history/**").permitAll()

                .antMatchers("/api/courses/all").permitAll()
                .antMatchers("/api/courses/create").permitAll()
                .antMatchers("/api/courses/update/{id}").permitAll()
                .antMatchers("/api/courses/delete/{id}").permitAll()

                .antMatchers("/api/orders/all").permitAll()
                .antMatchers("/api/orders/create").permitAll()
                .antMatchers("/api/orders/update/{id}").permitAll()
                .antMatchers("/api/orders/delete/{id}").permitAll()
                .antMatchers("/api/orders//OrderHistory/{idAccount}").permitAll()

                // auth accounts api tất cả truy cập
                .antMatchers("/api/admin/login").permitAll()
                .antMatchers("/api/user/login").permitAll()
                .antMatchers("/api/forgot-password").permitAll()
                .antMatchers("/api/reset-password").permitAll()
                .antMatchers("/api/change-password").permitAll()
                .antMatchers("/api/send-verification-email").permitAll()
                .antMatchers("/api/user-info").permitAll()
                .antMatchers("/api/register").permitAll()
                // auth accounts api tất cả truy cập

                // google O2Auth api tất cả truy cập
                .antMatchers("/api/google").permitAll()
                .antMatchers("/api/google/callback").permitAll()
                .antMatchers("/user/home").permitAll()
                // google O2Auth api tất cả truy cập

                // zalo page online payment
                .antMatchers("/api/zalopay/callback").permitAll()
                .antMatchers("/api/zalopay/check-transaction").permitAll()
                .antMatchers("/api/courses/**").permitAll()
                // zalo page online payment

                // websocket api tất cả truy cập
                .antMatchers("/ws/**").permitAll() // Cho phép tất cả các kết nối tới endpoint WebSocket
                .antMatchers("/topic/newUser").permitAll() // Cho phép tất cả các kết nối tới endpoint WebSocket
                .antMatchers("/topic").permitAll() // Cho phép tất cả các kết nối tới endpoint WebSocket
                .antMatchers("/app").permitAll() // Cho phép tất cả các kết nối tới endpoint WebSocket
                .antMatchers("/user/me").permitAll()
                // websocket api tất cả truy cập

                .anyRequest().authenticated();
               
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(Arrays.asList("*")); // Allow all origins
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
