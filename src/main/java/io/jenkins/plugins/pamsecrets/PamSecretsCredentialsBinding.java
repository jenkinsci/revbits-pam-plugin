package io.jenkins.plugins.pamsecrets;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 *
 * @author zunnuran-invozone
 */
public class PamSecretsCredentialsBinding extends MultiBinding<PamSecretsCredentials> {

    private static final Logger LOGGER = Logger.getLogger(PamSecretsCredentialsBinding.class.getName());

    @Symbol("RevBitsPAMSecretsCredentials")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<PamSecretsCredentials> {

        @Override
        public String getDisplayName() {
            return "RevBits PAM Secrets Credential";
        }

        @Override
        public boolean requiresWorkspace() {
            return false;
        }

        @Override
        protected Class<PamSecretsCredentials> type() {
            return PamSecretsCredentials.class;
        }

    }

    private String variable;
    private String credentialsId;

    @DataBoundConstructor
    public PamSecretsCredentialsBinding(String credentialsId){
        super(credentialsId);
    }

    @Override
    protected Class<PamSecretsCredentials> type() {
        return PamSecretsCredentials.class;
    }

    @Override
    public MultiEnvironment bind(Run<?, ?> build, FilePath workSpace, Launcher launcher, TaskListener listener) throws IOException, InterruptedException {
             LOGGER.log(Level.INFO, "public MultiEnvironment");
            PamSecretsCredentials pamSecretsCredentials = getCredentials(build);
        pamSecretsCredentials.setContext(build);


            return new MultiEnvironment(
                    Collections.singletonMap(variable, pamSecretsCredentials.getSecret(credentialsId, variable).getPlainText()));
    }

    @Override
    public Set<String> variables() {
        return null;
    }

    //    @Override
    public String getVariable() {
        return variable;
    }
    @DataBoundSetter
    public void setVariable(String variable) {
        this.variable = variable;
    }

    @DataBoundSetter
    public void setCredentialsId(String credentialsId) {
        this.credentialsId = credentialsId;
    }
}
