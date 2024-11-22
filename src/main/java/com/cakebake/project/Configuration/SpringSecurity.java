package com.cakebake.project.Configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import com.cakebake.project.Services.CustomUserDetailService;

@Configuration
@EnableWebSecurity
public class SpringSecurity {

        @Autowired
        GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;
        @Autowired
        private CustomUserDetailService customUserDetailService;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests((authorize) -> authorize
                                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                                .requestMatchers("/", "/shop", "/register", "/shop/viewproduct/{id}",
                                                                "/shop/category/{id}", "/login", "/ok", "/authenticate")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .sessionManagement(session -> session
                                                // .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                                .formLogin(form -> form
                                                .loginPage("/login")
                                                .permitAll()
                                                .failureUrl("/login?error=true")
                                                .successHandler(myAuthenticationSuccessHandler())
                                                .usernameParameter("email")
                                                .passwordParameter("password"))
                                .oauth2Login(oauth2 -> oauth2
                                                .loginPage("/login")
                                                .successHandler(googleOAuth2SuccessHandler))
                                .logout(logout -> logout
                                                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                                                .logoutSuccessUrl("/login")
                                                .invalidateHttpSession(true)
                                                .deleteCookies("JSESSIONID"))
                                .csrf(csrf -> csrf.disable())
                                .httpBasic(Customizer.withDefaults());

                return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public AuthenticationSuccessHandler myAuthenticationSuccessHandler() {
                return new CustomLoginSuccessHandler();
        }

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
                auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder());
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return (web) -> web
                                .ignoring()
                                .requestMatchers("/resources/**", "/static/**", "/images/**", "/productImages/**",
                                                "/css/**");
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
                return configuration.getAuthenticationManager();
        }
}