package io.jenkins.plugins.api;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;

import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.util.Secret;

public class PamAPI {

	public static boolean initialized = false;

	public static class PamAuthnInfo {
		String applianceUrl;
		Secret apiKey;

        public PamAuthnInfo(String applianceUrl, Secret apiKey) {
            this.applianceUrl = applianceUrl;
            this.apiKey = apiKey;
        }
	}

	public static class SecretResponse {
		public String value;
		public String errorMessage;
	}

	private static final Logger LOGGER = Logger.getLogger(PamAPI.class.getName());

	private static void defaultToEnvironment(PamAuthnInfo pamAuthn) {
		Map<String, String> env = System.getenv();
		if (pamAuthn.applianceUrl == null && env.containsKey("REVBITS_APPLIANCE_URL"))
			pamAuthn.applianceUrl = env.get("REVBITS_APPLIANCE_URL");
		if (pamAuthn.apiKey == null && env.containsKey("REVBITS_AUTHN_API_KEY"))
			pamAuthn.apiKey = Secret.fromString(env.get("REVBITS_AUTHN_API_KEY"));
	}

	public static String getSecretFromApi(PamAuthnInfo pamAuthn, String variable) throws IOException {
//		Declarations
		URL url;
		int status;

//		URL formation
		String urlString = String.format("%s/api/v1/secretman/getSecretV4/%s", pamAuthn.applianceUrl, variable);
		url = new URL(urlString);

//		Connection
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

		con.setRequestMethod("GET");
		con.setRequestProperty("apiKey", Secret.toString(pamAuthn.apiKey));
		LOGGER.log(Level.INFO, "Connection opened");

//		Response and Data Mapping
		status = con.getResponseCode();
		LOGGER.log(Level.INFO, "API call status: "+status);

		InputStream responseStream = con.getInputStream();
		ObjectMapper mapper = new ObjectMapper();

		SecretResponse sr = mapper.readValue(responseStream, SecretResponse.class);

//		Verification
		if (status != 200) {
			String error = "Error fetching secret from PAM ";
			LOGGER.log(Level.WARNING, error);
			if (sr.errorMessage != null) {
				error += "[ Status: " + status + ", Message: " + sr.errorMessage + " ]";
				LOGGER.log(Level.WARNING, error);
			} else {
				error += "[ Status: " + status + " ]";
				LOGGER.log(Level.WARNING, error);
			}
			LOGGER.log(Level.WARNING, error);
			throw new IOException(error);
		}
		if (sr.value == null || sr.value.equals("")) {
			LOGGER.log(Level.WARNING, "Incomplete data or No secret received against variable: " + variable);
			throw new IOException("Incomplete data or No secret received against variable: " + variable);
		}

		return sr.value;
	}

	private PamAPI() {
		super();
	}
}
