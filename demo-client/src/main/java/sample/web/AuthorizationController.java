package sample.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class AuthorizationController {
	private final WebClient webClient;
	private final String messagesBaseUri;

	public AuthorizationController(WebClient webClient,
			@Value("${messages.base-uri}") String messagesBaseUri) {
		this.webClient = webClient;
		this.messagesBaseUri = messagesBaseUri;
	}

	@GetMapping(value = "/authorize", params = "grant_type=authorization_code")
	public String authorizationCodeGrant(Model model,
			@RegisteredOAuth2AuthorizedClient("messaging-client-oidc")
					OAuth2AuthorizedClient authorizedClient) {

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);
		model.addAttribute("idToken", ((DefaultOidcUser)auth.getPrincipal()).getIdToken().getTokenValue());
		model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());

		return "index";
	}

	@GetMapping(value = "/authorize", params = "grant_type=client_credentials")
	public String clientCredentialsGrant(Model model,
										 @RegisteredOAuth2AuthorizedClient("messaging-client-client-credentials")
										 OAuth2AuthorizedClient authorizedClient) {

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String[] messages = this.webClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		model.addAttribute("messages", messages);
		model.addAttribute("idToken", ((DefaultOidcUser)auth.getPrincipal()).getIdToken().getTokenValue());
		model.addAttribute("accessToken", authorizedClient.getAccessToken().getTokenValue());

		return "index";
	}

	@ExceptionHandler(WebClientResponseException.class)
	public String handleError(Model model, WebClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

}
