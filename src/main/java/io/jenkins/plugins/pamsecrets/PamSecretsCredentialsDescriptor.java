package io.jenkins.plugins.pamsecrets;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import hudson.util.FormValidation;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.QueryParameter;

import java.net.MalformedURLException;
import java.net.URL;

public class PamSecretsCredentialsDescriptor extends CredentialsDescriptor {

//    VALIDATION - Appliance URL should be https://domain.com or https://sub.domain.com
    public FormValidation doCheckApplianceURL(@QueryParameter String value) {
        try {
            if(!value.equals("")) {
                String url = new URL(value).toString();
                int count = StringUtils.countMatches(url, "/");
                if (count > 2) {
                    return FormValidation.error("URL should not contain any path or extra slash. Should be specific to only domain.");
                }
            }
            return FormValidation.ok();
        } catch (MalformedURLException e) {
            return FormValidation.error("Not a valid URL");
        }
    }
}
