package in.bushansirgur.removebg.config;

import in.bushansirgur.removebg.security.ClerkJwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    public ClerkJwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/webhooks/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config = new CorsConfiguration();

        // Allow requests from your frontend
        config.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "http://localhost:3000",
                "https://removebg-topaz.vercel.app"
        ));

        // Allow all HTTP methods
        config.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));

        // Allow all headers (important for file uploads and various content types)
        config.setAllowedHeaders(List.of("*"));

        // Expose headers that frontend can read
        config.setExposedHeaders(List.of(
                "Authorization",
                "Content-Type"
        ));

        // Allow credentials (cookies, authorization headers)
        config.setAllowCredentials(true);

        // Cache preflight requests for 1 hour (reduces OPTIONS requests)
        config.setMaxAge(3600L);

        // Apply CORS configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}