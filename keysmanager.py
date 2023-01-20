import sys,os
import signal, subprocess


class KeysManager(object):

    ''' Certificate properties. '''
    CERT_KEY_BITS = 2048
    CERT_KEY_SIZE = CERT_KEY_BITS / 8
    CERT_ENCRYPTION = 'rsa:' + str(CERT_KEY_BITS)
    CERT_SUBJECT = '/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd'
    CERT_EXPIRE = 365
    CERT_DIGEST_NAME = 'sha1'
    CERT_DIGEST_BITS = 160
    CERT_DIGEST_SIZE = CERT_DIGEST_BITS / 8

    ''' Getters for private key. '''
    get_key_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.key'
    get_key_data = lambda self, peer_name: open(self.get_key_path(peer_name)).read()

    ''' Getters for public certiicate. '''
    get_cert_path = lambda self, peer_name: os.path.join(self.keys_dir, peer_name) + '.crt'
    get_cert_data = lambda self, peer_name: open(self.get_cert_path(peer_name)).read()

    def __init__(self, keys_dir, openssl_win32_dir = None):

        self.keys_dir = keys_dir        
        self.openssl_win32_config_path = None

        if sys.platform == 'win32':

            assert openssl_win32_dir is not None

            # generate path to the win32 openssl executable
            self.openssl_win32_dir = openssl_win32_dir
            self.openssl_win32_path = os.path.join(openssl_win32_dir, 'bin', 'openssl.exe')
            self.openssl_win32_config_path = os.path.join(openssl_win32_dir, 'share', 'openssl.cnf')

            if not os.path.isfile(self.openssl_win32_path):

                raise(IOError('%s is not found' % self.openssl_win32_path))

            # use win32 version
            self.openssl_command = self.openssl_win32_path

        else:

            # use version that installed into the host system
            self.openssl_command = 'openssl'

    def generate_files(self, peer_name):

        def prepare_file(file_path):

            if os.path.isfile(file_path):

                # delete existing file
                os.unlink(file_path)

            return file_path
        
        key_path  = prepare_file(self.get_key_path(peer_name))
        cert_path = prepare_file(self.get_cert_path(peer_name))

        print('Generating \"%s\" and \"%s\"' % (key_path, cert_path))

        args = [ self.openssl_command,
                 'req', '-x509', '-nodes',
                 '-newkey', self.CERT_ENCRYPTION, 
                 '-keyout', key_path,
                 '-out', cert_path,
                 '-days', str(self.CERT_EXPIRE),
                 '-subj', self.CERT_SUBJECT ]        

        if self.openssl_win32_config_path is not None:

            args += [ '-config', self.openssl_win32_config_path ]

        # generating self-signed certificate using OpenSLL
        subprocess.call(args)

        def check_file(file_path):

            # check that file was sucessfully generated
            if not file_path:

                raise(Exception('%s wasn\'t generated' % file_path))

            return file_path

        check_file(key_path)
        check_file(cert_path)

    def generate(self, peer_name, overwrite = False):

        if not overwrite:

            if os.path.isfile(self.get_key_path(peer_name)) and \
               os.path.isfile(self.get_cert_path(peer_name)):

                   sys.stdout.write('Certificate for %s is already exists, overwrite? [Y/N]: ' % peer_name)

                   if sys.stdin.read(1).lower() != 'y':
                   
                        print('\n *** Abort!')
                        return

        print('')

        self.generate_files(peer_name)

        print('')
