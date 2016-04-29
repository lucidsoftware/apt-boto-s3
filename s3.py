#!/usr/bin/env python2
import boto3
import botocore
import collections
import hashlib
import re
import signal
import sys
import threading
import urllib
import urlparse

class MessageHeader(collections.namedtuple('MessageHeader_', ['status_code', 'status_info'])):
    def __str__(self):
        return '{} {}'.format(self.status_code, self.status_info)

    @staticmethod
    def parse(line):
        status_code, status_info = line.split(' ', 1)
        return MessageHeader(int(status_code), status_info)

class MessageHeaders:
    CAPABILITIES = MessageHeader(100, 'Capabilities')
    STATUS = MessageHeader(102, 'Status')
    URI_FAILURE = MessageHeader(400, 'URI Failure')
    GENERAL_FAILURE = MessageHeader(401, 'General Failure')
    URI_START = MessageHeader(200, 'URI Start')
    URI_DONE = MessageHeader(201, 'URI Done')
    URI_ACQUIRE = MessageHeader(600, 'URI Acquire')
    CONFIGURATION = MessageHeader(601, 'Configuration')

class Message(collections.namedtuple('Message_', ['header', 'fields'])):
    @staticmethod
    def parse_lines(lines):
        return Message(MessageHeader.parse(lines[0]), tuple(re.split(': *', line, 1) for line in lines[1:]))

    def get_field(self, field_name):
        return next(self.get_fields(field_name), None)

    def get_fields(self, field_name):
        return (value for name, value in self.fields if name.lower() == field_name.lower())

    def __str__(self):
        lines = [str(self.header)]
        lines.extend('{}: {}'.format(name, value) for name, value in self.fields)
        lines.append('\n')
        return '\n'.join(lines)

Pipes = collections.namedtuple('Pipes', ['input', 'output'])

class AptMethod(collections.namedtuple('AptMethod_', ['pipes'])):
    def send(self, message):
        self.pipes.output.write(str(message))
        self.pipes.output.flush()

    def _send_error(self, message):
        self.send(Message(MessageHeaders.GENERAL_FAILURE, (('Message', message),)))

    def run(self):
        try:
            self.send_capabilities()

            # TODO: Use a proper executor. concurrent.futures has them, but it's only in Python 3.2+.
            threads = []
            interrupt = {'lock': threading.Lock(), 'value': False}

            lines = []
            while not interrupt['value']:
                line = sys.stdin.readline()
                if not line:
                    for thread in threads:
                        thread.join()
                    break
                line = line.rstrip('\n')
                if line:
                    lines.append(line)
                elif lines:
                    message = Message.parse_lines(lines)
                    lines = []
                    def handle_message():
                        try:
                            self.handle_message(message)
                        except Exception as ex:
                            with interrupt['lock']:
                                if not interrupt['value']:
                                    interrupt['value'] = True
                                    self._send_error(ex)
                            raise
                    thread = threading.Thread(target=handle_message)
                    threads.append(thread)
                    thread.start()
        except Exception as ex:
            self._send_error(ex)
            raise

class S3AptMethod(AptMethod):
    def __init__(self, *args, **kwargs):
        super(S3AptMethod, self).__init__(*args, **kwargs)
        self.signature_version = None

    class S3Uri:
        def __init__(self, method, raw_uri):
            self.method = method
            self.uri = urlparse.urlparse(raw_uri)

        def user_host(self):
            parts = self.uri.netloc.split('@', 1)
            return parts if len(parts) == 2 else None, parts[0]

        def endpoint_url(self):
            return 'https://{}/'.format(self.user_host()[1])

        def credentials(self):
            user, _ = self.user_host()
            if user:
                user_parts = user.split(':', 1)
                if len(user_parts) == 2:
                    return map(urllib.unquote, user_parts)
                else:
                    raise Exception('Access key and secret are specified improperly in the URL')
            return None, None

        def virtual_host_bucket(self):
            virtual_host_match = re.match('(?:(.*).|)s3(?:-[^.]*)?.amazonaws.com', self.uri.hostname)
            return virtual_host_match and virtual_host_match.group(1)

        def bucket_key(self):
            bucket = self.virtual_host_bucket()
            if bucket:
                key = self.uri.path[1:]
            else:
                _, bucket, key = map(urllib.unquote, self.uri.path.split('/', 2))
            return bucket, key

        def signature_version(self):
            if self.method.signature_version:
                return self.method.signature_version
            elif self.virtual_host_bucket() == '':
                return 's3v4'

    def send_capabilities(self):
        self.send(Message(MessageHeaders.CAPABILITIES, (
            ('Send-Config', 'true'),
            ('Pipeline', 'true'),
            ('Single-Instance', 'yes'),
        )))

    def handle_message(self, message):
        if message.header.status_code == MessageHeaders.CONFIGURATION.status_code:
            for config in message.get_fields('Config-Item'):
                key, value = config.split('=', 1)
                if key == 'S3::Signature::Version':
                    try:
                        self.signature_version = {'2':'s3', '4':'s3v4'}[value]
                    except KeyError:
                        raise Exception('Invalid value for S3::Signature::Version')
        elif message.header.status_code == MessageHeaders.URI_ACQUIRE.status_code:
            uri = message.get_field('URI')
            filename = message.get_field('Filename')
            s3_uri = self.S3Uri(self, uri)

            s3_access_key, s3_access_secret = s3_uri.credentials()
            s3 = boto3.resource(
                's3',
                aws_access_key_id=s3_access_key,
                aws_secret_access_key=s3_access_secret,
                endpoint_url=s3_uri.endpoint_url(),
                config=botocore.client.Config(signature_version=s3_uri.signature_version())
            )

            bucket, key = s3_uri.bucket_key()
            s3_object = s3.Bucket(bucket).Object(key)

            self.send(Message(MessageHeaders.STATUS, (
                ('Message', 'Requesting {}/{}'.format(bucket, key)),
                ('URI', uri),
            )))
            try:
                s3_request = {}
                last_modified = message.get_field('Last-Modified')
                if last_modified:
                    s3_request['IfModifiedSince'] = last_modified
                s3_response = s3_object.get(**s3_request)
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == '304':
                    self.send(Message(MessageHeaders.URI_DONE, (
                        ('Filename', filename),
                        ('IMS-Hit', 'true'),
                        ('URI', uri),
                    )))
                else:
                    self.send(Message(MessageHeaders.URI_FAILURE, (
                        ('Message', error.response['Error']['Message']),
                        ('URI', uri),
                    )))
            else:
                self.send(Message(MessageHeaders.URI_START, (
                    ('Last-Modified', s3_response['LastModified'].isoformat()),
                    ('Size', s3_response['ContentLength']),
                    ('URI', uri),
                )))

                md5 = hashlib.md5()
                sha1 = hashlib.sha1()
                sha256 = hashlib.sha256()
                sha512 = hashlib.sha512()
                with open(filename, 'wb') as f:
                    while True:
                        bytes = s3_response['Body'].read(16 * 1024)
                        if not bytes:
                            break
                        f.write(bytes)
                        md5.update(bytes)
                        sha1.update(bytes)
                        sha256.update(bytes)
                        sha512.update(bytes)
                self.send(Message(MessageHeaders.URI_DONE, (
                    ('Filename', filename),
                    ('Last-Modified', s3_response['LastModified'].isoformat()),
                    ('MD5-Hash', md5.hexdigest()),
                    ('MD5Sum-Hash', md5.hexdigest()),
                    ('SHA1-Hash', sha1.hexdigest()),
                    ('SHA256-Hash', sha256.hexdigest()),
                    ('SHA512-Hash', sha512.hexdigest()),
                    ('Size', s3_response['ContentLength']),
                    ('URI', uri),
                )))

if __name__ == '__main__':
    def signal_handler(signal, frame):
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    pipes = Pipes(sys.stdin, sys.stdout)
    S3AptMethod(pipes).run()
