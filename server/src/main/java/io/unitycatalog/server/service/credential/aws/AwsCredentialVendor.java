package io.unitycatalog.server.service.credential.aws;

import io.unitycatalog.server.exception.BaseException;
import io.unitycatalog.server.exception.ErrorCode;
import io.unitycatalog.server.persist.utils.ServerPropertiesUtils;
import io.unitycatalog.server.service.credential.CredentialContext;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

public class AwsCredentialVendor {

  private static final Logger LOGGER = LoggerFactory.getLogger(AwsCredentialVendor.class);

  private final Map<String, S3StorageConfig> s3Configurations;

  public AwsCredentialVendor() {
    this.s3Configurations = ServerPropertiesUtils.getInstance().getS3Configurations();
  }

  public Credentials vendAwsCredentials(CredentialContext context) {
    String base = context.getStorageBase();
    S3StorageConfig s3StorageConfig = s3Configurations.get(base);
    if (s3StorageConfig == null) {
      throw new BaseException(ErrorCode.FAILED_PRECONDITION, "S3 bucket configuration not found.");
    }

    if (s3StorageConfig.getSessionToken() != null && !s3StorageConfig.getSessionToken().isEmpty()) {
      // if a session token was supplied, then we will just return static session credentials
      return Credentials.builder()
          .accessKeyId(s3StorageConfig.getAccessKey())
          .secretAccessKey(s3StorageConfig.getSecretKey())
          .sessionToken(s3StorageConfig.getSessionToken())
          .build();
    }

    // TODO: cache sts client
    try {
      StsClient stsClient = getStsClientForStorageConfig(s3StorageConfig);

      // TODO: Update this with relevant user/role type info once available
      String roleSessionName = "uc-%s".formatted(UUID.randomUUID());
      String awsPolicy =
          AwsPolicyGenerator.generatePolicy(context.getPrivileges(), context.getLocations());

      AssumeRoleResponse response =
          stsClient.assumeRole(
              r ->
                  r.roleArn(s3StorageConfig.getAwsRoleArn())
                      .policy(awsPolicy)
                      .roleSessionName(roleSessionName)
                      .durationSeconds((int) Duration.ofHours(1).toSeconds()));
      Credentials credentials = response.credentials();
      return credentials;
    } catch (java.net.URISyntaxException e) {
      return null;
    }
  }

  private StsClient getStsClientForStorageConfig(S3StorageConfig s3StorageConfig)
      throws URISyntaxException {
    AwsCredentialsProvider credentialsProvider;
    if (s3StorageConfig.getSecretKey() != null && !s3StorageConfig.getAccessKey().isEmpty()) {
      credentialsProvider =
          StaticCredentialsProvider.create(
              AwsBasicCredentials.create(
                  s3StorageConfig.getAccessKey(), s3StorageConfig.getSecretKey()));
    } else {
      credentialsProvider = DefaultCredentialsProvider.create();
    }

    // TODO: should we try and set the region to something configurable or specific to the server
    // instead?
    URI endpointURI = new URI(s3StorageConfig.getEndpoint());
    return StsClient.builder()
        .credentialsProvider(credentialsProvider)
        .endpointOverride(endpointURI)
        .region(Region.of(s3StorageConfig.getRegion()))
        .build();
  }
}
