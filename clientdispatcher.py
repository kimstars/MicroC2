
class ClientDispatcher(object):

    CLIENT_SESSION_KEY_BITS = 128
    CLIENT_SESSION_KEY_SIZE = CLIENT_SESSION_KEY_BITS / 8

    def __init__(self, request, client_address):

        self.request = request
        self.client_address = client_address
        self.client_sock = None

        self.load_keys()

    def load_keys(self):
        ''' Initialize encryption keys and certificates '''

        self.crypt_send = None
        self.crypt_recv = None

        def cert_digest(peer_id):

            # get certificate path
            path = self.keys_manager.get_cert_path(peer_id)

            # load X509 certificate and compute hexadecimal digest
            cert = M2Crypto.X509.load_cert(path)
            return cert.get_fingerprint(self.keys_manager.CERT_DIGEST_NAME).upper()

        self.keys_manager = KeysManager(Conf.CERT_DIR_PATH)

        # load certificate and private key of server
        self.server_key = M2Crypto.RSA.load_key(
            self.keys_manager.get_key_path(Conf.CERT_NAME))
        self.server_cert = M2Crypto.X509.load_cert(
            self.keys_manager.get_cert_path(Conf.CERT_NAME))
        self.server_cert_digest = cert_digest(Conf.CERT_NAME)

    def _recv(self, size=None):

        ret = ''

        if size is None:

            return self.request.recv(BUFF_SIZE)

        while len(ret) < size:

            # receive specified amount of data
            data = self.request.recv(size - len(ret))
            assert len(data) > 0

            ret += data

        return ret

    def _send(self, data):

        ret = 0

        while ret < len(data):

            # send all of the data
            size = self.request.send(data[ret:])
            assert size > 0

            ret += size

        return ret

    def _do_auth(self):

        if self.crypt_send is not None and self.crypt_recv is not None:

            return True

        class RC4Stream(object):

            def __init__(self, client, key):

                self.client = client
                self.ctx_send, self.ctx_recv = Crypto.Cipher.ARC4.new(key), \
                    Crypto.Cipher.ARC4.new(key)

            def sendall(self, data):

                assert self.ctx_send is not None

                return self.client.request.sendall(self.ctx_send.encrypt(data))

            def send(self, data):

                return self.sendall(data)

            def recv(self, size):

                assert self.ctx_recv is not None

                return self.ctx_recv.encrypt(self.client.request.recv(size))

        # receive session key encrypted with the server public RSA key
        data = self._recv(self.keys_manager.CERT_KEY_SIZE)

        try:

            # decrypt PKCS#1 encoded data
            data = self.server_key.private_decrypt(
                data, M2Crypto.RSA.pkcs1_padding)
            
            fmt = 'I%ds%ds' % (self.keys_manager.CERT_DIGEST_SIZE,
                               self.CLIENT_SESSION_KEY_SIZE)

            # parse decrypted data
            ver, digest, key = struct.unpack(fmt, data)

        except:

            raise (Exception(
                'Bad authorization request received from %s:%d' % self.client_address))

        # check server certificate digest
        digest = ''.join(map(lambda b: '%.2X' % ord(b), digest))
        if digest != self.server_cert_digest:

            raise (Exception('Authorization failed for %s:%d' + self.client_address))

        if ver != Conf.CLIENT_VERSION:

            raise (Exception('Bad protocol version for %s:%d' %
                   self.client_address))

        # send MD5 hash of session key to client to proove successful auth
        self._send(hashlib.md5(key).digest())

        # initialize RC4 context for client traffic encryption
        return RC4Stream(self, key)

    def handle(self):

        def _client_sock_close():

            self.client_sock.close()
            self.client_sock = None

        addr = (Conf.MAPPER_HOST, random.randrange(
            Conf.MAPPER_PORT_MIN, Conf.MAPPER_PORT_MAX))
        mapper, helper = None, None

        try:

            # perform authentication
            stream = self._do_auth()

            # create client instance
            helper = ClientHelper(sock=stream)
            helper.client_id = helper.get_id()

            # create folders for client files
            helper.create_folders()

            log_write(u'SERVER: Client %s:%d connected (ID = %s, PID = %d, port = %d)\n' %
                      (self.client_address[0], self.client_address[1], helper.client_id, os.getpid(), addr[1]))

            helper.client_add(addr=self.client_address, map_port=addr[1], map_pid=os.getpid(),
                              os_version=helper.os_version(), hardware=helper.hardware_info(), info=helper.get_info())

            # start mapper to receive connections from the main process
            mapper = ClientMapper(addr, self)
            mapper.start()

            last_request = time.time()

            while True:

                sock_list = [self.request] if self.client_sock is None else \
                            [self.request, self.client_sock]

                # transfer data between sockets
                read, write, err = select.select(sock_list, [], [], 1)

                if self.request in read:

                    # receive data from the client
                    data = stream.recv(BUFF_SIZE)
                    if len(data) == 0:
                        break

                    # check for ping from the client
                    if re.search('^\{\{\{\$[0123456789abcdef]{8}\}\}\}$', data) is not None:

                        if Conf.VERBOSE:
                            log_write(u'SERVER: Ping from client %s:%d\n' %
                                      self.client_address)

                    elif self.client_sock is not None:

                        # send data to the main process
                        self.client_sock.sendall(data)

                    last_request = time.time()

                if self.client_sock in read:

                    data = None

                    try:

                        # receive data from the main process
                        data = self.client_sock.recv(BUFF_SIZE)
                        assert len(data) > 0

                    except:

                        data = None

                    if data is None:

                        _client_sock_close()

                    else:

                        # send data to the client
                        stream.send(data)

                if time.time() - last_request >= Conf.CLIENT_TIMEOUT:

                    log_write(u'SERVER: Client %s:%d timeout occured\n' %
                              self.client_address)
                    break

        except Exception:

            log_write(u'ERROR: Exception in handle():\n')
            log_write(u'-----------------------------------------\n')
            log_write(traceback.format_exc())
            log_write(u'-----------------------------------------\n')

        log_write(u'SERVER: Client %s:%d disconnected\n' % self.client_address)

        if self.client_sock is not None:

            _client_sock_close()

        if mapper is not None:

            mapper.stop()

        if helper is not None:

            helper.client_del()

        self.request.close()

