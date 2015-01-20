#!/usr/bin/env python
import argparse
import re
import socket
import sys
import telnetlib


def check_socket_error(fn):
    def wrapper(*args, **kwargs):
        this = args[0]
        try:
            return fn(*args, **kwargs)
        except socket.error as msg:
            App.close_session(this)
            sys.exit('%s: %s' % ('E_SOCKET', msg))
        except EOFError:
            App.close_session(this)
            sys.exit('%s: %s' % ('E_SOCKET', 'Client unexpectedly reached EOF'))
        except RouterException, e:
            App.close_session(this)
            sys.exit(e.message)

    return wrapper


class RouterException(Exception):
    pass


class App:
    _ERROR_INTERNAL = 'E_INTERNAL'
    _ERROR_USAGE = 'E_USAGE'
    _ERROR_PASSWORD = 'E_PASSWORD'
    _ERROR_ROUTER = 'E_ROUTER'

    def __init__(self, host, port, timeout, password):
        self._host = host
        self._port = port
        self._cmd_timeout = 2
        self._hostname = None
        self._timeout = timeout
        self._password = password
        self.tn = None

    @check_socket_error
    def __enter__(self):
        self.tn = telnetlib.Telnet(self._host, self._port)
        self.tn.read_until('Password:', self._cmd_timeout)
        self.tn.write(self._password + '\n')
        del self._password
        index, m, text = self.tn.expect(['.*Password:', '.*Bad Password!!!',
                                         '(.*)>'], self._cmd_timeout)
        if index == -1:
            raise RouterException('%s: %s [%s]' %
                                  (App._ERROR_ROUTER, 'Unexpected response from'
                                                      ' router after login',
                                   text))
        elif 0 <= index <= 1:
            raise RouterException('%s: %s' %
                                  (App._ERROR_PASSWORD,
                                   'Cannot login with provided password'))
        elif index == 2:
            self._hostname = m.group(1)
        self._send('sys stdio %d' % self._timeout)
        self._read()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        App.close_session(self)

    def _send(self, command=''):
        self.tn.write(command + '\n')
        if command:
            return self.tn.read_until(command, self._cmd_timeout)
        return ''

    def _read(self, timeout=None):
        buf = self.tn.read_until(self._hostname + '>', timeout or
                                 self._cmd_timeout)
        return buf[:-len(self._hostname + '>')] \
            if buf.endswith(self._hostname + '>') else buf

    def _expect(self, timeout=None):
        index, m, text = self.tn.expect([re.escape(self._hostname) + '>'],
                                        timeout or self._cmd_timeout)
        if m:
            return text[:-len(self._hostname + '>')], True
        else:
            return text, False

    @staticmethod
    def close_session(app):
        try:
            if app.tn and app.tn.get_socket():
                app.tn.write('exit\n')
                app.tn.read_all()
                app.tn.close()
        except (socket.error, EOFError, RouterException):
            pass
        app.tn = None

    @staticmethod
    def prepare_from_file(args):
        res = dict()
        if args.file:
            res['configuration_file'] = args.file
        return res

    def _do_from_file(self, configuration_file=None):
        parser = App.get_parser(False, False)
        if configuration_file:
            for lines in configuration_file:
                args = parser.parse_args(lines.split())
                self.run(args.action, **args.func(args))

    @staticmethod
    def parse_port(port_str):
        if port_str:
            port = int(port_str)
            if 0 <= port <= 65535:
                return port
            raise RouterException("%s: Ports must be in [0, 65535] range. "
                                  "You gave %s" % (App._ERROR_USAGE, port_str))

    @staticmethod
    def validate_port_ranges(sport, dport):
        if sport[1] - sport[0] == dport[1] - dport[0]:
            return sport, dport
        raise RouterException('%s: Ports\' ranges are not equal' %
                              App._ERROR_USAGE)

    @staticmethod
    def range_ports(port1, port2):
        if port2:
            return (port2, port1) if port2 < port1 else (port1, port2)
        else:
            return port1, port1

    @staticmethod
    def get_ports(ports_str):
        m = re.match('^(\d+)(?::(\d+))?$', ports_str)
        if m:
            return App.range_ports(*map(App.parse_port, m.group(1, 2)))
        raise RouterException('%s: Wrong parameter passed for ports %s' %
                              (App._ERROR_USAGE, ports_str))

    @staticmethod
    def get_ip(ip_str):
        def check_and_strip(ip_part_str):
            ip_part = int(ip_part_str)
            if 0 <= ip_part <= 255:
                return ip_part_str.lstrip('0')
            raise RouterException('%s: Wrong parameter passed for ip' %
                                  App._ERROR_USAGE)
        m = re.match('^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip_str)
        if m:
            return reduce(lambda acc, ip: acc + '.' + ip,
                          map(check_and_strip, m.group(1, 2, 3, 4)))
        raise RouterException('%s: Wrong parameter passed for ip address %s' %
                              (App._ERROR_USAGE, ip_str))

    @staticmethod
    def prepare_forward(args):
        res = dict()
        if args.forward_action == 'list':
            res["list_action"] = True
        else:
            if args.name and len(args.name) > 20:
                raise RouterException('%s: Rule name must be less than 20 '
                                      'symbols' % App._ERROR_USAGE)
            res["name"] = args.name
            res["add"] = args.add
            res["delete"] = args.delete
            res["ip"] = App.get_ip(args.ip)
            sport = App.get_ports(args.sport)
            res["sport"], res["dport"] = App.validate_port_ranges(sport,
                                                                  App.
                                                                  get_ports(
                                                                      args.
                                                                      dport
                                                                  )) \
                if args.dport else (sport, sport)
            res["protocol"] = args.protocol
        return res

    def _get_rules(self):
        rule_str = self._get_rules_str()
        index = -1
        rule_set_index = 1
        rules = []
        re_rule_set = re.compile('.*Server Set: (\d+)\s*$')
        re_rule_part_one = re.compile('\s*(?:\d+\s+(\d+)|(\d+))?.*?\s+(\d+)'
                                      '\s+-\s+(\d+)\s+(\d{1,3}\.\d{1,3}\.'
                                      '\d{1,3}\.\d{1,3})\s+(\d+)\s*')
        re_rule_part_two = re.compile('\s*(no|yes)\s+(\S+)\s+(\d+)\s+-\s+'
                                      '(\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.'
                                      '\d{1,3})\s+-\s+(\d{1,3}\.\d{1,3}\.'
                                      '\d{1,3}\.\d{1,3})\s*', re.IGNORECASE)
        rule_index = 2
        while True:
            line_index = rule_str.find('\n', index + 1)
            if line_index < 0:
                break
            line = rule_str[index + 1:line_index]
            index = line_index
            m = re_rule_set.match(line)
            if m:
                rule_set_index = int(m.group(1))
                rule_index = 2
            else:
                m = re_rule_part_one.match(line)
                if m:
                    line_index = rule_str.find('\n', index + 1)
                    if line_index < 0:
                        break
                    line = rule_str[index + 1:line_index]
                    index = line_index
                    m1 = re_rule_part_two.match(line)
                    if m1:
                        rule_index = int(m.group(1) or m.group(2) or
                                         rule_index)
                        rule = (rule_set_index, rule_index, int(m.group(3)),
                                int(m.group(4)), m.group(5),
                                int(m.group(6)), m1.group(1).lower(),
                                m1.group(2), int(m1.group(3)),
                                int(m1.group(4)), m1.group(5), m1.group(6))
                        rules.append(rule)
                        rule_index += 1
        return rules

    def _get_rules_str(self):
        buf = []
        self._send('ip nat server disp')
        text, eoc = self._expect(2)
        buf.append(text)
        self._send()
        while not eoc:
            text, eoc = self._expect(5)
            buf.append(text)
        return "".join(buf)

    @staticmethod
    def _is_rule_equal(ip, sport, dport, protocol, rule):
        return rule[6] == 'yes' and ip == rule[4] and sport == \
            (rule[2], rule[3]) \
            and dport == (rule[8], rule[9]) and protocol == rule[7]

    def _do_forward(self, ip=None, sport=None, dport=None, protocol='ALL',
                    add=False, delete=False, name=None, list_action=False):
        if list_action:
            print self._get_rules_str()
        elif add or delete:
            first_available, found_rule = None, False
            for rule in self._get_rules():
                if rule[6] == 'no' and not first_available:
                    first_available = rule[0], rule[1]
                if App._is_rule_equal(ip, sport, dport, protocol, rule):
                    first_available = rule[0], rule[1]
                    found_rule = True
                    break
            if add and not found_rule:
                self._send('ip nat server load %d' % first_available[0])
                self._send('ip nat server edit %d svrport %d %d' %
                           (first_available[1], sport[0], sport[1]))
                if name:
                    self._send('ip nat server edit %d rulename %s' %
                               (first_available[1], name))
                self._send('ip nat server edit %d intport %d %d' %
                           (first_available[1], dport[0], dport[1]))
                self._send('ip nat server edit %d forwardip %s' %
                           (first_available[1], ip))
                self._send('ip nat server edit %d protocol %s' %
                           (first_available[1], protocol))
                self._send('ip nat server edit %d active yes' %
                           first_available[1])
                self._send('ip nat server save')
                self._read()
            elif delete and found_rule:
                self._send('ip nat server load %d' % first_available[0])
                self._send('ip nat server edit %d active no' %
                           first_available[1])
                self._send('ip nat server save')
                self._read()

    @staticmethod
    def prepare_filter(args):
        res = dict()
        res['iface'] = args.interface
        res['rule_type'] = args.type
        res['direction'] = args.direction
        res['node'] = args.node
        res['rule_set'] = args.set if args.interface == 'wan' else \
            map(lambda x: x if x != 0 else 256, args.set)
        return res

    def _do_filter(self, iface, rule_type, direction, node, rule_set):
        if iface == 'wan':
            self._send('wan node index %d' % node)
            self._send('wan node filter %s %s %s' % (direction, rule_type,
                                                     ' '.join(map(
                                                         lambda x: str(x),
                                                         rule_set))))
            self._send('wan node save')
        else:
            self._send('lan index %d' % node)
            self._send('lan filter %s %s %s' % (direction, rule_type,
                                                ' '.join(map(lambda x: str(x),
                                                             rule_set))))
            self._send('lan save')
        self._read()

    @staticmethod
    def prepare_pvc_status(args):
        res = dict()
        res['channel'] = args.channel
        return res

    def _do_pvc_status(self, channel):
        self._send('show wan status')
        text, _ = self._expect(3)
        m = re.search('PVC-' + str(channel) + '\s+Status\s+=\s+([^\n]+)'
                                              '(?:\s+Ip\s+=\s+([^\n]+))?',
                      text, re.M | re.I)
        if m:
            groups = m.groups('0.0.0.0')
            print 'status=' + groups[0].strip().lower()
            print 'ip=' + groups[1].strip()

    def _do_adsl_status(self):
        self._send('wan adsl status')
        text, _ = self._expect(3)
        m = re.search('current modem status:\s+([^\n]+)', text, re.I)
        if m:
            print m.group(1).strip().lower()

    @staticmethod
    def prepare_pppoe(args):
        res = dict()
        res['pvc'] = args.pvc
        res['drop'] = args.drop
        res['connect'] = args.connect
        return res

    def _do_pppoe(self, pvc, drop=False, connect=False):
        if drop or connect:
            self._send('sys pvc0poeretry ' + ('1' if connect else '0'))
            self._read()
            self._send('poe drop poe' + str(pvc))

    @staticmethod
    def prepare_adsl(args):
        res = dict()
        res['command'] = args.command
        return res

    def _do_adsl(self, command):
        self._send('wan adsl ' + command)
        self._read()

    @staticmethod
    def prepare_reboot(args):
        return dict()

    def _do_reboot(self):
        self._send('set reboot')

    @staticmethod
    def prepare(action):
        action_method = 'prepare_' + action.replace('-', '_')
        try:
            return getattr(App, action_method)
        except AttributeError:
            raise RouterException('%s: %s [%s]' %
                                  (App._ERROR_INTERNAL,
                                   'Cannot extract parameters for action',
                                   action))

    def _do_action(self, action, **kwargs):
        action_method = '_do_' + action
        try:
            getattr(self, action_method)(**kwargs)
        except AttributeError:
            raise RouterException('%s: %s [%s]' %
                                  (self._ERROR_INTERNAL,
                                   'Cannot find action', action))

    @check_socket_error
    def run(self, action, **kwargs):
        if self.tn and action:
            self._do_action(action.replace('-', '_'), **kwargs)
        else:
            raise RouterException('%s: %s [%s]' %
                                  (self._ERROR_INTERNAL,
                                   'Cannot execute an action', action))

    @staticmethod
    def get_parser(include_router_details=True, include_file_parser=True):
        parser = argparse.ArgumentParser(prog='Zyxel P-660HN-T1A router client',
                                         description='Run telnet commands '
                                                     'on Zyxel P-660HN-T1A')
        if include_router_details:
            parser.add_argument('-s', '--host', dest='host', required=True,
                                help='Hostname where router works')
            parser.add_argument('-c', '--password', dest='password',
                                required=True, help='Password to login router')
            parser.add_argument('-p', '--port', dest='port', default=23,
                                type=int, required=False, help='Port number to '
                                                               'login router')
            parser.add_argument('-t', '--timeout', dest='timeout', type=int,
                                default=360, required=False,
                                help='Router session timeout')

        subparsers = parser.add_subparsers(dest='action')

        if include_file_parser:
            config_parser = subparsers.add_parser('from-file')
            config_parser.add_argument('-f', '--file',
                                       type=argparse.FileType('r'),
                                       required=True)
            config_parser.set_defaults(func=App.prepare('from-file'))

        forward_parser = subparsers.add_parser('forward')
        forward_subparsers = forward_parser. \
            add_subparsers(dest='forward_action')
        forward_subparsers.add_parser('list')
        forward_parser_modify = forward_subparsers.add_parser('change')
        forward_group = forward_parser_modify. \
            add_mutually_exclusive_group(required=True)
        forward_group.add_argument('-a', '--add', action='store_true')
        forward_group.add_argument('-d', '--delete', action='store_true')
        forward_parser_modify.add_argument('-sport', required=True)
        forward_parser_modify.add_argument('-dport')
        forward_parser_modify.add_argument('-name')
        forward_parser_modify.add_argument('-ip', required=True)
        forward_parser_modify.add_argument('-p', '--protocol',
                                           choices=['ALL', 'UDP', 'TCP'],
                                           default='ALL')
        forward_parser.set_defaults(func=App.prepare('forward'))

        pvc_status_parser = subparsers.add_parser('pvc-status')
        pvc_status_parser.add_argument('--channel', default=0, type=int,
                                       choices=range(0, 7))
        pvc_status_parser.set_defaults(func=App.prepare('pvc-status'))

        adsl_status_parser = subparsers.add_parser('adsl-status')
        adsl_status_parser.set_defaults(func=lambda _: dict())

        pppoe_parser = subparsers.add_parser('pppoe')
        pppoe_group = pppoe_parser.add_mutually_exclusive_group(required=True)
        pppoe_group.add_argument('-d', '--drop', action='store_true')
        pppoe_group.add_argument('-c', '--connect', action='store_true')
        pppoe_parser.add_argument('-pvc', default=0, type=int,
                                  choices=range(0, 7))
        pppoe_parser.set_defaults(func=App.prepare('pppoe'))

        adsl_parser = subparsers.add_parser('adsl')
        adsl_parser.add_argument('--command', default='open',
                                 choices=('open', 'close', 'reset'))
        adsl_parser.set_defaults(func=App.prepare('adsl'))

        filter_parser = subparsers.add_parser('filter')
        filter_parser.add_argument('-i', '--interface',
                                   choices=['lan', 'wan'],
                                   default='wan')
        filter_parser.add_argument('-t', '--type',
                                   choices=['generic', 'tcpip'],
                                   default='tcpip')
        filter_parser.add_argument('-d', '--direction',
                                   choices=['incoming', 'outgoing'],
                                   default='incoming')
        filter_parser.add_argument('-n', '--node', default=1, type=int,
                                   choices=range(1, 8))
        filter_parser.add_argument('-s', '--set', required=True, nargs=4,
                                   type=int, choices=range(0, 12))
        filter_parser.set_defaults(func=App.prepare('filter'))

        reboot_parser = subparsers.add_parser('reboot')
        reboot_parser.set_defaults(func=App.prepare('reboot'))
        return parser

    @staticmethod
    def interact():
        try:
            args = App.get_parser().parse_args()
            return {'password': args.password, 'host': args.host,
                    'port': args.port, 'action': args.action,
                    'timeout': args.timeout, 'parameters': args.func(args)}
        except RouterException, error:
            sys.exit(error.message)


if __name__ == '__main__':
    cli = App.interact()
    with App(cli['host'], cli['port'], cli['timeout'], cli['password']) as r:
        r.run(cli['action'], **cli['parameters'])