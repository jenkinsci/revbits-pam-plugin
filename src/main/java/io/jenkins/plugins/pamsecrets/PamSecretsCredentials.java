package io.jenkins.plugins.pamsecrets;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import hudson.model.Run;
import hudson.util.Secret;

import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author zunnuran-invozone
 */
@NameWith(value = PamSecretsCredentials.NameProvider.class, priority = 1)
public interface PamSecretsCredentials extends StandardCredentials {

    static Logger getLogger() {
        return Logger.getLogger(PamSecretsCredentials.class.getName());
    }

    class NameProvider extends CredentialsNameProvider<PamSecretsCredentials> {

        @Override
        public String getName(PamSecretsCredentials ps) {
            return ps.getDisplayName() + ps.getNameTag() + " (" + ps.getDescription() + ")";
        }
    }

    String getDisplayName();
    String getNameTag();
    Secret getSecret(String credentialsId, String variable);
    String getApplianceURL();
    Secret getApiKey();
    void setContext(Run<?, ?> context);
}
