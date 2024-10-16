package io.unitycatalog.server.service.credential.aws;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class S3StorageConfig {
  private final String bucketPath;
  private final String region;
  private final String awsRoleArn;
  private final String accessKey;
  private final String secretKey;
  private final String sessionToken;
  private final String endpoint = "http://s3.gaia.local";
}
