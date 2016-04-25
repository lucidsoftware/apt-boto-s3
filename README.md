# apt-boto-s3

The *fast* and *simple* S3 transport for apt.

Access S3-hosted apt repositories via the AWS APIs.

## Why apt-boto-s3?

The most widely deployed package management system meets one of the largest cloud storage providers. Perfect.

While there are alternative apt transports for S3, like [apt-transport-s3](https://github.com/BashtonLtd/apt-transport-s3) or [apt-s3/apt-transport-s3](https://github.com/castlabs/apt-s3), this project has

* standard AWS credential resolution, including environment variables and ~/.aws/credentials
* pipelining requests for faster updates
* Last-Modified caching
* broad AWS API support, e.g. v4 credentials
* operability with any S3-compatible API
* Apache 2.0 license

## Installing

There's not a debian package (yet) for apt-boto-s3, but installation is straightforward.

Python 2.7 and the AWS Python SDK (boto) are required.

```
apt-get install python python-pip
pip install apt-boto-s3
```

Then add the `s3` transport method

```
curl -o /usr/lib/apt/methods/s3 https://raw.githubusercontent.com/castlabs//master/s3.py
chmod 755 /usr/lib/apt/methods/s3
```

## Usage

### URLs

The URL in apt sources can have any of the formats [documented](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro) by AWS.

```
# virtual-hosted style (any region)
deb http://my-bucket.s3.amazonaws.com jessie main contrib

# path style
deb http://s3.amazonaws.com/my-bucket jessie main contrib

# path style for region other than us-east-1
deb http://s3-sa-east-1.amazonaws.com/my-bucket jessie main contrib
```

Any endpoint can be used that has an S3-compatible API.

```
deb http://swift.example.com/my-bucket jessie main contrib
```

### Credentials

Credentials are resolved in the usual manner.

1. Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
1. Credentials file: `~/.aws/credentials`
1. Instance metadata: http://169.254.169.254
