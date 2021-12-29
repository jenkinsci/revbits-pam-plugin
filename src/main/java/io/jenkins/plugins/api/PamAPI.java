package io.jenkins.plugins.api;

import hudson.model.Run;
import okhttp3.*;
import org.json.JSONObject;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.github.mervick.aes_everywhere.Aes256;

public class PamAPI {

	public static class PamAuthnInfo {
		String applianceUrl;
		String apiKey;

        public PamAuthnInfo(String applianceUrl, String apiKey) {
            this.applianceUrl = applianceUrl;
            this.apiKey = apiKey;
        }
                
	}

	private static final Logger LOGGER = Logger.getLogger(PamAPI.class.getName());

	private static void defaultToEnvironment(PamAuthnInfo pamAuthn) {
		Map<String, String> env = System.getenv();
		if (pamAuthn.applianceUrl == null && env.containsKey("REVBITS_APPLIANCE_URL"))
			pamAuthn.applianceUrl = env.get("REVBITS_APPLIANCE_URL");
		if (pamAuthn.apiKey == null && env.containsKey("REVBITS_AUTHN_API_KEY"))
			pamAuthn.apiKey = env.get("REVBITS_AUTHN_API_KEY");
	}

	public static String getAuthorizationToken(OkHttpClient client, PamAuthnInfo pamAuthn,
			Run<?, ?> context) throws IOException {

		String resultingToken = null;

		if (pamAuthn.apiKey != null) {
			LOGGER.log(Level.INFO, "Authenticating with RevBits PAM");

			Request request = new Request.Builder()
					.url(String.format("%s/authenticate", pamAuthn.applianceUrl))
					.post(RequestBody.create(MediaType.parse("text/plain"), pamAuthn.apiKey)).build();

			Response response = client.newCall(request).execute();

			resultingToken = Base64.getEncoder().withoutPadding()
					.encodeToString(response.body().string().getBytes("UTF-8"));
			LOGGER.log(Level.INFO, () -> "RevBits PAM Authenticate response " + response.code() + " - " + response.message());

			if (response.code() != 200) {
				throw new IOException("Error authenticating to RevBits PAM [" + response.code() + " - " + response.message()
						+ "\n" + resultingToken);
			}
		} else {
			LOGGER.log(Level.INFO, "Failed to find credentials for RevBits RevBits PAM authentication");
		}

		return resultingToken;
	}


	public static OkHttpClient getHttpClient() {
		return new OkHttpClient.Builder().build();
	}

	public static String getSecretFromApi(OkHttpClient client, PamAuthnInfo pamAuthn,
								   String credentialsId, String variable) throws IOException, Exception {
		try {
			String result = "";
			long keyA = 0;
			long keyB = 0;

			long sharedKeyA = 0;
			long sharedKeyB = 0;

			long prime = 23;
			long generated = 9;

			long privateKeyA = Math.round(Math.random() * (9 - 2 + 1) + 2);
			long privateKeyB = Math.round(Math.random() * (9 - 2 + 1) + 2);
			long publicKeyA = Math.round(Math.pow(generated, privateKeyA) % prime);
			long publicKeyB = Math.round(Math.pow(generated, privateKeyB) % prime);

			Request request = new Request.Builder().url(
					String.format("%s/api/v1/secretman/GetSecretV2/%s", pamAuthn.applianceUrl, variable))
					.get().addHeader("apiKey", pamAuthn.apiKey)
					.addHeader("publicKeyA", String.valueOf(publicKeyA))
					.addHeader("publicKeyB", String.valueOf(publicKeyB))
					.build();

			Response response = client.newCall(request).execute();
			assert response.body() != null;
			result = response.body().string();

			if (response.code() != 200) {
				throw new IOException("Error fetching secret from PAM [" + response.code() + "]");
			}

			JSONObject obj = new JSONObject(result);
			if (!obj.getString("value").equals("") &&
				!obj.isNull("keyA") &&
				!obj.isNull("keyB")
			) {
				result = obj.getString("value");
				keyA = obj.getLong("keyA");
				keyB = obj.getLong("keyB");
			} else {
				LOGGER.log(Level.WARNING, "Incomplete data or No secret received against variable: " + variable);
			}

			sharedKeyA = (long) Math.pow(keyA, privateKeyA) % prime;
			sharedKeyB = (long) Math.pow(keyB, privateKeyB) % prime;

			BigInteger bSharedKeyA = new BigInteger(String.valueOf(sharedKeyA));
			BigInteger bSharedKeyB = new BigInteger(String.valueOf(sharedKeyB));
			BigInteger finalSecret = bSharedKeyA.pow(bSharedKeyB.intValue());

			return Aes256.decrypt(result, String.valueOf(finalSecret));
		}
		catch (IOException e){
			LOGGER.log(Level.INFO, "An exception occurred while fetching credentials.");
			e.printStackTrace();
			return "";
		}
	}


	private PamAPI() {
		super();
	}

}
