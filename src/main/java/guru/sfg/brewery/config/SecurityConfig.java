package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncodingFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return SfgPasswordEncodingFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorise -> authorise
                        .antMatchers("/", "/login" ,"/webjars/**", "/resources/**").permitAll()
                        .antMatchers("/beers/find", "/beers*").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                        .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN").build();
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
    //        UserDetails scott = User.withDefaultPasswordEncoder()
//                .username("scott")
//                .password("tiger")
//                .roles("CUSTOMER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, user, scott);
//    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                .password("{bcrypt}$2a$12$.PWp/XAnxtq21tARtIO6M.GzyJrCCkvTRA.rIWcoTLvn/ZbWlmLmC")
                .roles("ADMIN")
                .and()
                .withUser("user")
                .password("{sha256}1c394f7e031a16a4a2e747abea500f04218968f2d76c39e66c7233f93325f9c681058525c77b6175")
                .roles("USER")
                .and()
                .withUser("scott")
                .password("{bcrypt15}$2a$15$OYsmDVOmBVq54aIhcu.Em.4CgeaorDGHMDGAVDYtFroypgNHWDhsy")
                .roles("CUSTOMER");
    }
}
