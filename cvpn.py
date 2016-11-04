#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import sys
import os
import json
import logging
from contextlib import contextmanager, closing
import atexit
import traceback
from cStringIO import StringIO
import csv
from collections import namedtuple
import itertools
import getpass
import string

import yaml
import boto3
import colorama
import paramiko
import pystache

__author__ = 'Flier Lu <flier.lu@gmail.com>'

DEFAULT_LOGGING_FORMAT = '%(asctime)s [%(process)d:%(threadName)s] %(name)s %(levelname)s %(message)s'

CLOUD_VPN_TAG = 'cloud-vpn'

VPN_L2TP_IPSEC = 'L2TP/IPSec'
VPN_OPENVPN = 'OpenVPN'
VPN_OPENVPN_HTTPS = 'OpenVPN/HTTPS'
VPN_SOFTETHER = 'SoftEther'

MAX_TRY_TIMES = 3

INSTANCE_STATE_PENDING = 0
INSTANCE_STATE_RUNNING = 16
INSTANCE_STATE_SHUTTING_DOWN = 32
INSTANCE_STATE_TERMINATED = 48
INSTANCE_STATE_STOPPING = 64
INSTANCE_STATE_STOPPED = 80

INSTANCE_STATE_NAMES = {
    INSTANCE_STATE_PENDING: 'pending',
    INSTANCE_STATE_RUNNING: 'running',
    INSTANCE_STATE_SHUTTING_DOWN: 'shutting down',
    INSTANCE_STATE_TERMINATED: 'terminated',
    INSTANCE_STATE_STOPPING: 'stopping',
    INSTANCE_STATE_STOPPED: 'stopped',
}

Container = namedtuple('Container', ['name', 'id', 'image', 'status', 'labels'])
Image = namedtuple('Image', ['id', 'repo', 'tag'])


def genpass(pw_len=8, user_uppercase=True, use_digits=True, use_punctuation=False):
    import random

    pwlist = []

    while len(pwlist) < pw_len:
        pwlist.append(string.ascii_lowercase[random.randrange(len(string.ascii_lowercase))])

        if user_uppercase:
            pwlist.append(string.ascii_uppercase[random.randrange(len(string.ascii_uppercase))])

        if use_digits:
            pwlist.append(string.digits[random.randrange(len(string.digits))])

        if use_punctuation:
            pwlist.append(string.punctuation[random.randrange(len(string.punctuation))])

    pwlist = pwlist[:pw_len]

    random.shuffle(pwlist)

    return "".join(pwlist)

DEFAULT_PS_FORMAT = '{{.Names}}\t{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Labels}}'
DEFAULT_IMAGES_FORMAT = '{{.ID}}\t{{.Repository}}\t{{.Tag}}'
DEFAULT_VPN_REPO = 'siomiz/softethervpn'
DEFAULT_VPN_USER = getpass.getuser()
DEFAULT_VPN_PASS = genpass(12)
DEFAULT_VPN_PSK = genpass(12)

TPL_VPN_SERVICES = pystache.parse(u'''
VPN services {{name}} is {{status}}
===
IP Address  : {{public_ip_address}}
{{#running}}
Started at  : {{started_at}}
{{/running}}
{{#l2tp_ipsec}}
L2TP/IPSec  : enabled
    username: {{username}}
    password: {{password}}
    psk     : {{psk}}
{{/l2tp_ipsec}}
''')

log = logging.getLogger('main')


def parse_cmdline():
    import argparse

    parser = argparse.ArgumentParser()

    group = parser.add_argument_group('common')

    group.add_argument('--color', metavar='MODE', choices=['on', 'off', 'auto'], default='auto',
                       help='Enable colorized output. (default: auto)')

    group = parser.add_argument_group('vpn')

    group.add_argument('--vpn-name', metavar='NAME', default=CLOUD_VPN_TAG,
                       help='name of VPN services. (default: %s)' % CLOUD_VPN_TAG)
    group.add_argument('--vpn-tag', metavar='TAG', default=CLOUD_VPN_TAG,
                       help='run VPN with tag. (default: %s)' % CLOUD_VPN_TAG)
    group.add_argument('--vpn-image', metavar='NAME', default=DEFAULT_VPN_REPO,
                       help='run VPN container base on image. (default: %s)' % DEFAULT_VPN_REPO)
    group.add_argument('--vpn-user', metavar='USER', default=DEFAULT_VPN_USER,
                       help='username of VPN service. (default: %s)' % DEFAULT_VPN_USER)
    group.add_argument('--vpn-pass', metavar='PASS', default=DEFAULT_VPN_PASS,
                       help='password of VPN service. (default: %s)' % DEFAULT_VPN_PASS)
    group.add_argument('--vpn-psk', metavar='KEY', default=DEFAULT_VPN_PSK,
                       help='VPN Pre-Shared Key (PSK). (default: %s)' % DEFAULT_VPN_PSK)

    group.add_argument('--vpn-services', action='append', default=[])
    group.add_argument('--l2tp-ipsec', dest='vpn_services', action='append_const', const=VPN_L2TP_IPSEC,
                       help='enable L2TP/IPSec service.')
    group.add_argument('--openvpn', dest='vpn_services', action='append_const', const=VPN_OPENVPN,
                       help='enable OpenVPN service')
    group.add_argument('--openvpn-https', dest='vpn_services', action='append_const', const=VPN_OPENVPN_HTTPS,
                       help='enable OpenVPN over HTTPS service')
    group.add_argument('--softether', dest='vpn_services', action='append_const', const=VPN_SOFTETHER,
                       help='enable SoftEther service')

    group = parser.add_argument_group('ssh')

    group.add_argument('--ssh-user', metavar='USER', default='ec2-user',
                       help='the username to authenticate as (defaults: ec2-user)')
    group.add_argument('--ssh-timeout', metavar='SECS', type=int,
                       help='timeout (in seconds) for the TCP connect')

    def host_key_policy(policy):
        if policy == 'auto':
            return paramiko.AutoAddPolicy()
        elif policy == 'reject':
            return paramiko.RejectPolicy()
        elif policy == 'warn':
            return paramiko.WarningPolicy()

        return None

    group.add_argument('--ssh-host-key-policy', metavar='POLICY',
                       choices=['reject', 'auto', 'warn'], default='auto', type=host_key_policy,
                       help='policy to use when connecting to servers without a known host key.')

    group = parser.add_argument_group('aws')

    group.add_argument('--region', default=os.getenv('AWS_REGION'), help='AWS region to use.')
    group.add_argument('--profile', default=os.getenv('AWS_PROFILE'), help='AWS profile to use.')
    group.add_argument('--access-key', metavar='KEY', default=os.getenv('AWS_ACCESS_KEY_ID'),
                       help='The access key for AWS account.')
    group.add_argument('--secret-key', metavar='KEY', default=os.getenv('AWS_SECRET_ACCESS_KEY'),
                       help='The secret key for AWS account.')
    group.add_argument('--session-token', metavar='TOKEN', default=os.getenv('AWS_SESSION_TOKEN'),
                       help='The session key for AWS account.')
    group.add_argument('--dry-run', action='store_true',
                       help='Checks whether you have the required permissions for the action, '
                            'without actually making the request, and provides an error response.')

    group = parser.add_argument_group('logging')

    group.add_argument('-d', '--debug', action='store_const', const=logging.DEBUG, dest='logging_level')
    group.add_argument('-v', '--verbose', action='store_const', const=logging.INFO, dest='logging_level')
    group.add_argument('--logging-format', metavar='FORMAT')
    group.add_argument('--logging-file', type=file)
    group.add_argument('--logging-config', metavar='FILE')
    group.add_argument('--logging-config-port', metavar='PORT', type=int)

    return parser.parse_args()


color_theme = lambda _: ''


def init_color_theme(color):
    if color == 'off':
        return lambda _: ''

    if color == 'auto' and 'color' not in os.getenv('TERM'):
        return lambda _: ''

    colorama.init(autoreset=True)

    atexit.register(colorama.deinit)

    return lambda name: dict(ok=colorama.Fore.LIGHTGREEN_EX,
                             err=colorama.Fore.RED).get(name, '')


def init_logging(logging_level, logging_format, logging_file, logging_config=None, logging_config_port=None):
    if logging_config is None:
        logging.basicConfig(level=logging_level or logging.WARN,
                            format=logging_format or DEFAULT_LOGGING_FORMAT,
                            filename=logging_file,
                            stream=sys.stderr)
    elif logging_config.endswith('.yaml') or logging_config.endswith('.yml'):
        with open(logging_config, 'r') as f:
            logging.config.dictConfig(yaml.load(f))
    else:
        logging.config.fileConfig(logging_config)

    if logging_config_port is not None:
        logging.config.listen(logging_config_port).start()

        atexit.register(logging.config.stopListening)

    atexit.register(logging.shutdown)


class AWSClient(object):
    def __init__(self, region=None, profile=None, access_key=None, secret_key=None, session_token=None, dry_run=False):
        self.log = logging.getLogger('aws')
        self.session = boto3.Session(aws_access_key_id=access_key,
                                     aws_secret_access_key=secret_key,
                                     aws_session_token=session_token,
                                     region_name=region,
                                     profile_name=profile)
        self.dry_run = dry_run

        self.log.info("use AWS region `%s` with profile `%s`", self.session.region_name, self.session.profile_name)

    def close(self):
        pass

    @property
    def ec2(self):
        return self.session.resource('ec2')

    def find_instances(self, name=None):
        self.log.info("find instances (name=%s)", name)

        filters = []

        if name:
            filters.append(dict(Name='tag:Name', Values=[name]))

        return self.ec2.instances.filter(Filters=filters)

    def start_instance(self, instance):
        self.log.info("start instance `%s`", instance.instance_id)

        instance.start(DryRun=self.dry_run)

    def wait_until_running(self, instance):
        self.log.info("wait until instance `%s` running", instance.instance_id)

        instance.wait_until_running(DryRun=self.dry_run)


class SSHClient(object):
    def __init__(self, host_key_policy):
        self.log = logging.getLogger('ssh')

        self.ssh = paramiko.SSHClient()
        self.ssh.load_system_host_keys()

        if os.path.exists(self.host_key_filename):
            self.ssh.load_host_keys(self.host_key_filename)

        self.ssh.set_missing_host_key_policy(host_key_policy)

    def close(self):
        self.ssh.close()

    @property
    def conf_dir(self):
        return os.path.expanduser('~/.cloud-ssh')

    @property
    def host_key_filename(self):
        return os.path.join(self.conf_dir, 'hosts')

    def close(self):
        if not os.path.exists(self.conf_dir):
            os.makedirs(self.conf_dir, 0755)

        self.ssh.save_host_keys(self.host_key_filename)
        self.ssh.close()

    def connect(self, uri, timeout):
        from urlparse import urlparse

        u = urlparse(uri)

        self.log.info("connect to %s", uri)

        self.ssh.connect(u.hostname,
                         username=u.username,
                         password=u.password,
                         key_filename=u.path,
                         timeout=timeout)

    def find_ssh_key(self, fingerprint):
        self.log.info("finding SSH key with fingerprint: %s", fingerprint)

        fp = ''.join([chr(int(b, 16)) for b in fingerprint.split(':')])

        for root, dirs, files in os.walk(os.path.expanduser('~/.ssh')):
            for name in files:
                filename = os.path.join(root, name)

                if self.key_fingerprint(filename) == fp:
                    self.log.info("found SSH private key with same fingerprint: %s", filename)

                    return filename

        return None

    @staticmethod
    def key_fingerprint(filename):
        import hashlib

        from cryptography.hazmat.primitives import serialization

        private_key = paramiko.RSAKey.from_private_key_file(filename)

        der_encoded_key = private_key.key.private_bytes(encoding=serialization.Encoding.DER,
                                                        format=serialization.PrivateFormat.PKCS8,
                                                        encryption_algorithm=serialization.NoEncryption())

        return hashlib.sha1(der_encoded_key).digest()

    def exec_cmd(self, args, timeout=None):
        cmdline = ' '.join(args if type(args) == list else [args])

        self.log.info("executing command: " + cmdline)

        stdin, stdout, stderr = self.ssh.exec_command(cmdline, timeout=timeout)

        out = stdout.read()

        if out:
            self.log.debug('execute command:\n' + out)

        err = stderr.read()

        if err:
            self.log.warning("fail to execute command:\n" + err)

        return out, err


class DockerException(Exception):
    def __init__(self, msg):
        super.__init__(msg)


class DockerClient(object):
    def __init__(self, ssh):
        self.log = logging.getLogger('docker')
        self.ssh = ssh

    def close(self):
        self.ssh.close()

    def images(self, name=None, timeout=None, show_all=False, format=DEFAULT_IMAGES_FORMAT):
        args = ['sudo', 'docker', 'images', '--format', "'%s'" % format]

        if name:
            args += [name]

        self.log.info("list %s images with name=%s", 'all' if show_all else 'named', name)

        out, err = self.ssh.exec_cmd(args, timeout=timeout)

        images = [Image(*row) for row in csv.reader(StringIO(out), dialect=csv.excel_tab)]

        self.log.info("found %d images: %s", len(images), ["%s:%s" % (i.repo, i.tag) for i in images])

        return images

    def ps(self, label=None, timeout=None, show_all=False, format=DEFAULT_PS_FORMAT):
        args = ['sudo', 'docker', 'ps']

        if show_all:
            args += ['-a']

        if label:
            args += ['--filter', 'label='+label]

        args += ['--format', "'%s'" % format]

        self.log.info("list %s containers with label=%s", 'all' if show_all else 'running', label)

        out, err = self.ssh.exec_cmd(args, timeout=timeout)

        containers = [Container(*row) for row in csv.reader(StringIO(out), dialect=csv.excel_tab)]

        self.log.info("found %d containers: %s", len(containers), [c.id for c in containers])

        return containers

    def start(self, container_id, timeout=None):
        args = ['sudo', 'docker', 'start', container_id]

        self.log.info("starting container %s", container_id)

        self.ssh.exec_cmd(args, timeout=timeout)

    def inspect(self, id, timeout=None):
        args = ['sudo', 'docker', 'inspect', id]

        self.log.info("inspect container or image %s", id)

        out, err = self.ssh.exec_cmd(args, timeout=timeout)

        return json.loads(out)

    def pull(self, image, timeout=None):
        args = ['sudo', 'docker', 'pull', image]

        self.log.info("pulling image %s", image)

        self.ssh.exec_cmd(args, timeout=timeout)

    def run(self, image,
            name=None,
            detach=True,
            labels=None,
            restart=None,
            network=None,
            privileged=False,
            caps=None,
            ports=None,
            env=None,
            timeout=None):

        args = ['sudo', 'docker', 'run']

        if name:
            args += ['--name', name]

        if detach:
            args += ['--detach']

        if labels:
            args += itertools.chain(*[['--label', label] for label in labels])

        if restart:
            args += ['--restart', restart]

        if network:
            args += ['--net', network]

        if privileged:
            args += ['--privileged']

        if caps:
            args += itertools.chain(*[['--cap-add', cap] for cap in caps])

        if ports:
            args += itertools.chain(*[['-p', port] for port in ports])

        if env:
            args += itertools.chain(*[['-e', '%s=%s' % (key, value)] for key, value in env.items()])

        args += [image]

        self.log.info("run container base on image %s", image)

        self.ssh.exec_cmd(args, timeout=timeout)


@contextmanager
def step(msg, line_width=64):
    print(msg + ' ...' + ' '*(line_width-len(msg)-10), end='')

    try:
        yield

        print(color_theme('ok') + '[ok]')
    except BaseException as ex:
        print(color_theme('err') + '[fail]')

        log.info("step `%s` failed, %s", msg, ex)
        log.debug(''.join(traceback.format_exception(*sys.exc_info())))


class CloudVPN(object):
    def __init__(self, aws, tag):
        self.log = logging.getLogger('cloud-vpn')
        self.aws = aws
        self.tag = tag

    def find_vpn_instances(self):
        instances = list(self.aws.find_instances(name=self.tag))

        log.info("found %d cloud VPN instances: %s",
                 len(instances),
                 ', '.join([i.instance_id for i in instances]))

        return instances

    def ensure_instance_is_running(self, instance):
        state = instance.state['Code']

        if state == INSTANCE_STATE_STOPPING:
            self.log.info('wait instance `%s` until stopped', instance.instance_id)

            self.aws.wait_until_stopped(instance)

            state = INSTANCE_STATE_STOPPED

        if state == INSTANCE_STATE_STOPPED:
            self.log.info('start the stopped instance `%s`', instance.instance_id)

            self.aws.start_instance(instance)

            state = INSTANCE_STATE_PENDING

        if state == INSTANCE_STATE_PENDING:
            self.log.info('wait instance `%s` until running', instance.instance_id)

            self.aws.wait_until_running(instance)

            state = INSTANCE_STATE_RUNNING

        return state == INSTANCE_STATE_RUNNING

    def connect_instance(self, instance, host_key_policy, timeout=None):
        ssh = SSHClient(host_key_policy)

        key_filename = ssh.find_ssh_key(self.aws.ec2.KeyPair(instance.key_name).key_fingerprint)

        uri = 'ssh://%s@%s%s' % (opts.ssh_user, instance.public_ip_address, key_filename or '')

        self.log.info("connect to instance `%s` @ %s", instance.instance_id, uri)

        ssh.connect(uri, timeout=timeout)

        return ssh

    def run_vpn_container(self, docker, image, name, username, password, psk,
                          l2tp_ipsec=True, openvpn=True, openvpn_https=True, softether=False):
        ports = []

        if l2tp_ipsec:
            ports += ['500:500/udp', '4500:4500/udp', '1701:1701/tcp']

        if openvpn:
            ports += ['1194:1194/udp']

        if openvpn_https:
            ports += ['443:443/tcp']

        if softether:
            ports += ['5555:5555/tcp']

        env = {
            'USERNAME': username,
            'PASSWORD': password,
            'PSK': psk,
        }

        docker.run(image,
                   name,
                   detach=True,
                   labels=[self.tag],
                   restart='always',
                   network='host',
                   privileged=True,
                   caps=['NET_ADMIN'],
                   ports=ports,
                   env=env)

    def dump_vpn_info(self, instance, container):
        ports = container['Config']['ExposedPorts']
        env = dict([var.split('=') for var in container['Config']['Env']])

        print(pystache.Renderer().render(TPL_VPN_SERVICES, {
            'public_ip_address': instance.public_ip_address,
            'name': container['Name'],
            'status': container['State']['Status'],
            'running': container['State']['Running'],
            'started_at': container['State']['StartedAt'],
            'l2tp_ipsec': '500/udp' in ports,
            'openvpn': '1194/udp' in ports,
            'softether': '5555/tcp' in ports,
            'username': env.get('USERNAME'),
            'password': env.get('PASSWORD'),
            'psk': env.get('PSK')
        }))

if __name__ == '__main__':
    opts = parse_cmdline()

    color_theme = init_color_theme(opts.color)

    init_logging(opts.logging_level,
                 opts.logging_format,
                 opts.logging_file,
                 opts.logging_config,
                 opts.logging_config_port)

    log.debug("parsed cmdline: %s", vars(opts))

    with closing(AWSClient(opts.region,
                           opts.profile,
                           opts.access_key,
                           opts.secret_key,
                           opts.session_token,
                           opts.dry_run)) as aws:

        cloud = CloudVPN(aws, tag=opts.vpn_tag)

        with step('check cloud VPN instances status'):
            vpn_instances = cloud.find_vpn_instances()

        for vpn_instance in vpn_instances:
            with step('ensure cloud VPN instance is running'):
                if not cloud.ensure_instance_is_running(vpn_instance):
                    log.info("skip instance `%s` in %s", vpn_instance.instance_id, vpn_instance.state)

                    continue

            with step('connect to cloud VPN instance `%s`' % vpn_instance.instance_id):
                ssh = cloud.connect_instance(vpn_instance,
                                             host_key_policy=opts.ssh_host_key_policy,
                                             timeout=opts.ssh_timeout)

            with closing(DockerClient(ssh)) as docker:
                for _ in range(MAX_TRY_TIMES):
                    containers = docker.ps(show_all=True, label=opts.vpn_tag)

                    vpn_container = None

                    with step('check cloud VPN container status'):
                        for container in containers:
                            if container.status.startswith('Up'):
                                vpn_container = container
                                break
                            elif container.status.startswith('Exited'):
                                vpn_container = container
                                break

                    if vpn_container is None:
                        for _ in range(MAX_TRY_TIMES):
                            with step('check cloud VPN image `%s`' % opts.vpn_image):
                                images = docker.images(opts.vpn_image)

                            if images:
                                break

                            with step('pull cloud VPN image `%s`' % opts.vpn_image):
                                docker.pull(opts.vpn_image)

                        if not images:
                            raise DockerException("fail to pull image `%s`" % opts.vpn_image)

                        with step('run VPN container `%s`' % opts.vpn_name):
                            cloud.run_vpn_container(docker,
                                                    image=opts.vpn_image,
                                                    name=opts.vpn_name,
                                                    username=opts.vpn_user,
                                                    password=opts.vpn_pass,
                                                    psk=opts.vpn_psk,
                                                    l2tp_ipsec=VPN_L2TP_IPSEC in opts.vpn_services,
                                                    openvpn=VPN_OPENVPN in opts.vpn_services,
                                                    openvpn_https=VPN_OPENVPN_HTTPS in opts.vpn_services,
                                                    softether=VPN_SOFTETHER in opts.vpn_services)

                            continue

                    if vpn_container.status.startswith('Exited'):
                        with step('starting cloud VPN container `%s`' % vpn_container.id):
                            docker.start(vpn_container.id)

                    with step('inspect cloud VPN container `%s`' % vpn_container.id):
                        vpn_services = docker.inspect(vpn_container.id)

                    if vpn_services[0]['State']['Running']:
                        cloud.dump_vpn_info(vpn_instance, vpn_services[0])

                        break
