package io.jenkins.plugins.exceptions;

public class InvalidPamSecretException
  extends RuntimeException {

    /**
   *
   */
  private static final long serialVersionUID = 1L;

  public InvalidPamSecretException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }

    public InvalidPamSecretException(String errorMessage) {
        super(errorMessage);
    }

}