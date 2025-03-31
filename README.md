
# s3-signer APISIX Plugin

A custom plugin for [Apache APISIX](https://apisix.apache.org/) that transparently signs requests to S3-compatible storage backends using AWS Signature Version 4 (SigV4).

## How It Works

This plugin intercepts requests to S3 endpoints, computes the appropriate AWS Signature V4 headers using provided credentials, and forwards the signed request to the S3-compatible backend.

## Plugin Configuration

### Required Parameters

| Name           | Type   | Description                    |
|----------------|--------|--------------------------------|
| `access_key`   | string | AWS access key ID              |
| `secret_key`   | string | AWS secret access key          |
| `region`       | string | AWS region (e.g. `us-east-1`)  |
| `service`      | string | AWS service (default: `s3`)    |

### Example

```json
{
  "uri": "/s3/*",
  "plugins": {
    "s3-signer": {
      "access_key": "YOUR_ACCESS_KEY",
      "secret_key": "YOUR_SECRET_KEY",
      "region": "us-east-1",
      "service": "s3"
    }
  },
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "s3.amazonaws.com:443": 1
    },
    "scheme": "https"
  }
}
```
