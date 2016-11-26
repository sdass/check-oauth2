package com.example;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.autoconfigure.web.ResourceProperties;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@EnableOAuth2Sso // must required
@EnableAuthorizationServer // must required
@SpringBootApplication
@RestController
//@Order(6)
public class CheckOauth2Application extends WebSecurityConfigurerAdapter {
	
	@Autowired
	OAuth2ClientContext oAuth2ClientContext;

	public static void main(String[] args) {
		SpringApplication.run(CheckOauth2Application.class, args);
	}
	
	@RequestMapping({"/user", "/me"})
	public Map<String, String> login(Principal principal, HttpServletRequest request){
		System.out.println("login() method called . . .uri=" + request.getRequestURI());
		Map<String, String> map = new LinkedHashMap<String, String>();
		map.put("user", principal.getName());
		return map;
	}
	

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
	

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
		}
	}//class ends
	
	
	//private CompositeFilter ssoFilter(){
	private Filter ssoFilter(){
		CompositeFilter compositeFilter = new CompositeFilter();
		List<Filter> filters = new ArrayList<Filter>();
		
		//facebook filter
		OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
		//OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebookAuthServer(), oAuth2ClientContext);
		OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook().getClient(), oAuth2ClientContext);
		facebookFilter.setRestTemplate(facebookTemplate);
		//UserInfoTokenService -- constructor saying this client can access the resource on the url
		//String userInfoEndpointUrl = facebookResource().getUserInfoUri();
		String userInfoEndpointUrl = facebook().getResource().getUserInfoUri();
		
		String clientId = facebook().getClient().getClientId();
		System.out.println("constructor args: " + "userInfoEndpointUrl=" + userInfoEndpointUrl + " clientId=" + clientId);
		
		facebookFilter.setTokenServices(new UserInfoTokenServices(userInfoEndpointUrl, clientId)); //(tokenServices);
		filters.add(facebookFilter);

		//github filter
		OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
		OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github().getClient(), oAuth2ClientContext);
		githubFilter.setRestTemplate(githubTemplate);
		String userInfoEndpointGit = github().getResource().getUserInfoUri();
		String clientIdGit = github().getClient().getClientId();
		System.out.println("constructor args: " + "userInfoEndpointGit=" + userInfoEndpointGit + " clientIdGit=" + clientIdGit );
		githubFilter.setTokenServices(new UserInfoTokenServices(userInfoEndpointGit, clientIdGit));
		filters.add(githubFilter);
		compositeFilter.setFilters(filters);
		return compositeFilter;
	}
		

	@SuppressWarnings("deprecation")
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter){
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}
	
	@Bean //must
	@ConfigurationProperties("github")
	public ClientResources github(){
		return new ClientResources();
	}

	@Bean //must
	@ConfigurationProperties("facebook")
	public ClientResources facebook(){
		return new ClientResources();
	}	
	
	class ClientResources {
		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails cleint = new AuthorizationCodeResourceDetails();
		
		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();
		
		public AuthorizationCodeResourceDetails getClient(){
			return cleint;
		}
		
		public ResourceServerProperties getResource() {
			return resource;
		}
		
	}
		
}
