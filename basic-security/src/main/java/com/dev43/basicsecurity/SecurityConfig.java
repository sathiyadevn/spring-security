package com.dev43.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/h2-console/**").permitAll()       // h2 db
                        .anyRequest().authenticated());

        //        http.formLogin(withDefaults());         // 1
        http.httpBasic(withDefaults());    // 2
        http.sessionManagement(session ->   // 3
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));        //
//      h2 db   4
        http.headers(headers ->
//                headers.frameOptions(frameOptions-> frameOptions.sameOrigin()));
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

//        http.csrf(csrf-> csrf.disable());
        http.csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(){
        UserDetails user1= User.withUsername("user1")
                .password("{noop}user1Pass")        // {noop} -> password save as plain text, not base64
                .roles("USER")
                .build();
        UserDetails admin= User.withUsername("admin")
                .password("{noop}adminPass")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user1,admin);
    }
}
