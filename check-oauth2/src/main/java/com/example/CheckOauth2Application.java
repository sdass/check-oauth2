package com.example;

import java.security.Principal;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.autoconfigure.web.ResourceProperties;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@EnableOAuth2Sso
@SpringBootApplication
@RestController
public class CheckOauth2Application extends WebSecurityConfigurerAdapter {
	
	@Autowired
	OAuth2ClientContext oAuth2ClientContext;

	public static void main(String[] args) {
		SpringApplication.run(CheckOauth2Application.class, args);
	}
	
	@RequestMapping("/user")
	public Principal login(Principal principal){
		System.out.println("login() method called . . .");
		return principal;
	}
	
	
	/*
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
		.authorizeRequests().and()
		.antMatcher("/**")
		//. . . . 
		.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
		.logout().logoutSuccessUrl("/").permitAll()
		.and().authorizeRequests().antMatchers("/", "/user", "login").permitAll();	
		
	}
	*/
	

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
				.authenticated().and().exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
				.logoutSuccessUrl("/").permitAll().and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
	}

	private Filter ssoFilter(){
		OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
		OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebookAuthServer(), oAuth2ClientContext);
		facebookFilter.setRestTemplate(facebookTemplate);
		//UserInfoTokenService -- constructor saying this client can access the resource on the url
		String userInfoEndpointUrl = facebookResource().getUserInfoUri();
		
		String clientId = facebookAuthServer().getClientId();
		System.out.println("constructor args: " + "userInfoEndpointUrl=" + userInfoEndpointUrl + " clientId=" + clientId);
		
		facebookFilter.setTokenServices(new UserInfoTokenServices(userInfoEndpointUrl, clientId)); //(tokenServices);
		
		return facebookFilter;
	}
	

	@SuppressWarnings("deprecation")
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter){
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("facebook.client")
	public AuthorizationCodeResourceDetails facebookAuthServer(){
		AuthorizationCodeResourceDetails authCodeResourceDetail = new AuthorizationCodeResourceDetails();
		System.out.println("facebook.client=" + authCodeResourceDetail);
		return authCodeResourceDetail;
	}
	
	@Bean
	@Primary
	@ConfigurationProperties("facebook.resource")
	public ResourceServerProperties facebookResource(){
		
		ResourceServerProperties resourceserverProp = new ResourceServerProperties();
		//resourceserverProp.setId("233668646673605"); //client id  -- sdass added clientId: 233668646673605
		System.out.println("facebook.resource=" + resourceserverProp);
		return resourceserverProp;
	}
		
}
