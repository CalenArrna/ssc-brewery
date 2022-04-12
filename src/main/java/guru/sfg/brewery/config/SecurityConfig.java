package guru.sfg.brewery.config;

import guru.sfg.brewery.security.JpaUserDetailService;
import guru.sfg.brewery.security.RestHeaderAuthenticationFilter;
import guru.sfg.brewery.security.RestUrlAuthenticationFilter;
import guru.sfg.brewery.security.SfgPasswordEncodingFactories;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    @Autowired
//    JpaUserDetailService jpaUserDetailService;

    public RestHeaderAuthenticationFilter restHeaderAuthenticationFilter(AuthenticationManager authenticationManager) {
        RestHeaderAuthenticationFilter filter = new RestHeaderAuthenticationFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public RestUrlAuthenticationFilter restUrlAuthenticationFilter(AuthenticationManager authenticationManager) {
        RestUrlAuthenticationFilter filter = new RestUrlAuthenticationFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return SfgPasswordEncodingFactories.createDelegatingPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(restHeaderAuthenticationFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .csrf().disable();

        http.addFilterBefore(restUrlAuthenticationFilter(authenticationManager()),
                UsernamePasswordAuthenticationFilter.class);

        http
                .authorizeRequests(authorise -> authorise
                        .antMatchers("/h2-console/**").permitAll()
                        .antMatchers("/", "/login", "/webjars/**", "/resources/**").permitAll()
                        .antMatchers("/beers/find", "/beers*").permitAll()
                        .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                        .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();

//        H2 Console Config, make frames work, and see db
        http.headers().frameOptions().sameOrigin();
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

//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(jpaUserDetailService).passwordEncoder(passwordEncoder());
//
//
////        auth.inMemoryAuthentication()
////                .withUser("spring")
////                .password("{bcrypt}$2a$12$.PWp/XAnxtq21tARtIO6M.GzyJrCCkvTRA.rIWcoTLvn/ZbWlmLmC")
////                .roles("ADMIN")
////                .and()
////                .withUser("user")
////                .password("{sha256}1c394f7e031a16a4a2e747abea500f04218968f2d76c39e66c7233f93325f9c681058525c77b6175")
////                .roles("USER")
////                .and()
////                .withUser("scott")
////                .password("{bcrypt12}$2a$15$OYsmDVOmBVq54aIhcu.Em.4CgeaorDGHMDGAVDYtFroypgNHWDhsy")
////                .roles("CUSTOMER");
//    }
}
