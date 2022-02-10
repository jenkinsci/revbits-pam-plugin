package io.jenkins.plugins.pamsecrets;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.model.Run;
import hudson.util.Secret;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;

import io.jenkins.plugins.api.PamAPI;
import io.jenkins.plugins.exceptions.InvalidPamSecretException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 *
 * @author zunnuran-invozone
 */

public class PamSecretsCredentialsImpl extends BaseStandardCredentials implements PamSecretsCredentials {

    @Extension
    public static class DescriptorImpl extends PamSecretsCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "RevBits PAM Secret Credential";
        }

    }

    public static String getDescriptorDisplayName() {
        return "RevBits PAM Secrets Credential";
    }

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(PamSecretsCredentialsImpl.class.getName());

    private String credentialsID;
    private String applianceURL;
    private Secret apiKey;
    private Secret publicKey;

    private transient Run<?, ?> context;


    @DataBoundConstructor
    public PamSecretsCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                                     @CheckForNull String variablePath, @CheckForNull String description) {
        super(scope, id, description);
    }

    public String getCredentialsID() {
        LOGGER.log(Level.INFO, "Get Credentials");
        return credentialsID;
    }

    @DataBoundSetter
    public void setCredentialsID(String credentialsID) {
        LOGGER.log(Level.INFO, "Set Credentials");
        this.credentialsID = credentialsID;
    }


    public String getDisplayName() {
        return "RevBits PAM Secrets";
    }

    public String getNameTag() {
        return "/*****";
    }

    public Secret getSecret(String credentialsId, String variable) {

        String secret = "";
        try {
            PamAPI.PamAuthnInfo pamAuthn = new PamAPI.PamAuthnInfo(applianceURL, apiKey, publicKey);
            secret = PamAPI.getSecretFromApi(pamAuthn, variable);

        } catch (Exception e) {
            throw new InvalidPamSecretException(e.getMessage());
        }

        return Secret.fromString(secret);
    }

    @Override
    public void setContext(Run<?, ?> context) {
        LOGGER.log(Level.INFO, "Set Context");
        if (context != null)
            this.context = context;
    }

    @Override
    public String getApplianceURL() {
        return applianceURL;
    }

    @DataBoundSetter
    public void setApplianceURL(String applianceURL) {
        this.applianceURL = applianceURL;
    }

    @Override
    public Secret getApiKey() {
        return this.apiKey;
    }

    @DataBoundSetter
    public void setApiKey(Secret apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    public Secret getPublicKey() {
        return this.publicKey;
    }

    @DataBoundSetter
    public void setPublicKey(Secret publicKey) {
        this.publicKey = publicKey;
    }

}
