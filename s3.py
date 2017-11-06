#!/usr/bin/env python2
import boto3
import botocore
import collections
import hashlib
import Queue
import re
import signal
import socket
import sys
import threading
import urllib
import urlparse

class Interrupt():
    def __init__(self):
        self.lock = threading.Lock()
        self.interrupted = False

    def __nonzero__(self):
        return self.interrupted

    def interupt(self):
        with self.lock:
            if not self.interrupted:
                self.interrupted = True
                return True
        return False

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

class AptIO(object):
    @staticmethod
    def input(input):
        def read_one():
            lines = []
            while True:
                line = input.readline()
                if not line:
                    return None
                line = line.rstrip('\n')
                if line:
                    lines.append(line)
                elif lines:
                    return Message.parse_lines(lines)
        return iter(read_one, None)

    @staticmethod
    def output(output):
        def send_one(message):
            output.write(str(message))
            output.flush()
        return send_one

class AptMethod(object):
    def __init__(self, pipes):
        self.input = AptIO.input(pipes.input)
        self.output = AptIO.output(pipes.output)

class AptRequest(collections.namedtuple('AptRequest_', ['output'])):
    def handle_message(self, message):
        try:
            self._handle_message(message)
        except Exception as ex:
            exc_tb = sys.exc_info()[2]
            message = '{} ({}, line {})'.format(ex, exc_tb.tb_frame.f_code.co_filename, exc_tb.tb_lineno)
            self.output(Message(MessageHeaders.GENERAL_FAILURE, (('Message', message),)))

class PipelinedAptMethod(AptMethod):

    class Output(object):
        def __init__(self, method):
            self.method = method
            self.queue = Queue.Queue()
            self.method.queues.put(self.queue)

        def __enter__(self):
            return self.queue.put

        def __exit__(self, type, value, traceback):
            self.queue.put(None)

        def send(self, message):
            if message.header != MessageHeaders.GENERAL_FAILURE:
                self.queue.put(message)
            elif self.method.interrupt:
                self.queue.put(message)

    def __init__(self, method_type, pipes):
        super(PipelinedAptMethod, self).__init__(pipes)
        self.interrupt = Interrupt()
        self.method_type = method_type
        self.queues = Queue.Queue()

    def _send_queue_thread(self):
        def f():
            # try:
                for queue in iter(self.queues.get, None):
                    for message in iter(queue.get, None):
                        self.output(message)
            # except IOError:
            #     pass
        thread = threading.Thread(target=f)
        thread.start()
        return thread

    def _handle_message_thread(self, message):
        pipelined_output = self.Output(self)
        def f():
            with pipelined_output as output:
                self.method_type.request(output).handle_message(message)
        thread = threading.Thread(target=f)
        thread.start()
        return thread

    def run(self):
        self.output(Message(MessageHeaders.CAPABILITIES, self.method_type.capabilities()))
        # TODO: Use a proper executor. concurrent.futures has them, but only in Python 3.2+.
        threads = [self._send_queue_thread()]
        for message in self.input:
            if self.interrupt:
                break
            threads.append(self._handle_message_thread(message))
        self.queues.put(None)
        for thread in threads:
            thread.join()

class S3AptMethodType(object):
    def request(self, output):
        return S3AptRequest(output)

    def capabilities(self):
        return (
            ('Send-Config', 'true'),
            ('Pipeline', 'true'),
            ('Single-Instance', 'yes'),
        )

class S3AptRequest(AptRequest):
    def __init__(self, output):
        super(S3AptRequest, self).__init__(output)
        self.signature_version = None

    class S3Uri:
        def __init__(self, request, raw_uri):
            self.request = request
            self.uri = urlparse.urlparse(raw_uri)
            # parse host as if it were an AWS host
            match = re.match('(.+\.|)?s3(?:[-.]([^.]*))?.amazonaws.com', self.uri.hostname)
            self.virtual_host_bucket, self.region = (match.groups() if match else (None, None))

        def user_host(self):
            parts = self.uri.netloc.split('@', 1)
            return parts if len(parts) == 2 else (None, parts[0])

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

            if self.role_arn is not None:
                creds_rsp = boto3.client('sts').assume_role(
                    RoleArn=self.role_arn,
                    RoleSessionName=socket.gethostname().replace('.', '-'),
                )
                if "Credentials" not in creds_rsp:
                    return None, None

                return creds_rsp["Credentials"]["AccessKeyId"],
                creds_rsp["Credentials"]["SecretAccessKey"]

            return None, None

        def bucket_key(self):
            if self.virtual_host_bucket:
                key = self.uri.path[1:]
            else:
                _, bucket, key = map(urllib.unquote, self.uri.path.split('/', 2))
            return bucket, key

        def signature_version(self):
            if self.request.signature_version:
                return self.request.signature_version
            elif self.virtual_host_bucket == '':
                return 's3v4'

    def _handle_message(self, message):
        if message.header.status_code == MessageHeaders.CONFIGURATION.status_code:
            for config in message.get_fields('Config-Item'):
                key, value = config.split('=', 1)
                if key == 'S3::Signature::Version':
                    try:
                        self.signature_version = {'2':'s3', '4':'s3v4'}[value]
                    except KeyError:
                        raise Exception('Invalid value for S3::Signature::Version')
                if key == 'S3::Credentials::RoleArn':
                    self.role_arn = value
        elif message.header.status_code == MessageHeaders.URI_ACQUIRE.status_code:
            uri = message.get_field('URI')
            filename = message.get_field('Filename')
            s3_uri = self.S3Uri(self, uri)

            access_key, access_secret = s3_uri.credentials()
            bucket, key = s3_uri.bucket_key()

            region = s3_uri.region
            if not region and s3_uri.virtual_host_bucket:
                # find bucket's region
                session = boto3.session.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=access_secret,
                    region_name='us-east-1',
                )
                s3_client = session.client('s3')
                region = s3_client.get_bucket_location(Bucket=bucket)['LocationConstraint'] or 'us-east-1'
            session = boto3.session.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=access_secret,
                region_name=region or 'us-east-1',
            )
            s3 = session.resource('s3',
                config=botocore.client.Config(signature_version=s3_uri.signature_version()),
                endpoint_url=s3_uri.endpoint_url(),
            )
            s3_object = s3.Bucket(bucket).Object(key)

            self.output(Message(MessageHeaders.STATUS, (
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
                    self.output(Message(MessageHeaders.URI_DONE, (
                        ('Filename', filename),
                        ('IMS-Hit', 'true'),
                        ('URI', uri),
                    )))
                else:
                    self.output(Message(MessageHeaders.URI_FAILURE, (
                        ('Message', error.response['Error']['Message']),
                        ('URI', uri),
                    )))
            else:
                self.output(Message(MessageHeaders.URI_START, (
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
                self.output(Message(MessageHeaders.URI_DONE, (
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
    # interrupt signals are sometimes sent
    def signal_handler(signal, frame):
        pass
    signal.signal(signal.SIGINT, signal_handler)

    PipelinedAptMethod(S3AptMethodType(), Pipes(sys.stdin, sys.stdout)).run()
