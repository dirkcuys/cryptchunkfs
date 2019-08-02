#!/usr/bin/env python

import os
import sys
import errno
import hashlib
from collections import defaultdict

from fuse import FUSE, FuseOSError, Operations
from stat import S_IFDIR, S_IFLNK, S_IFREG

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from datetime import datetime
from time import time
import json


files = {
    '/': {
        'meta': dict(
            st_mode=(S_IFDIR | 0o755),
            st_ctime=datetime(2019,1,1).timestamp(),
            st_mtime=datetime(2019,1,1).timestamp(),
            st_atime=datetime(2019,1,1).timestamp(),
            st_nlink=2
        )
    },
    '/bob.md': {
        'meta': dict(
            st_mode=(S_IFREG | 0o755),
            st_ctime=datetime(2019,1,1).timestamp(),
            st_mtime=datetime(2019,1,1).timestamp(),
            st_atime=datetime(2019,1,1).timestamp(),
            st_nlink=1,
            st_size=8
        ),
        'data': b'abcdefgh',
    }
}


def debug(f):
    def _f(*args, **kwargs):
        print(f'Calling {f.__name__} ({args} {kwargs})')
        ret = f(*args, **kwargs)
        #print(f'Returning {ret}')
        return ret
    return _f


def _read_chunks(chunks, key):
    """ read all chunks in an array and return data """
    data = b''
    backend = default_backend()
    for chunk_name in chunks:
        with open(chunk_name, 'rb') as chunk_file:
            iv = chunk_file.read(16)
            encrypted_chunk = chunk_file.read()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            data += decryptor.update(encrypted_chunk) + decryptor.finalize()
    return data


class Passthrough(Operations):
    def __init__(self, root):
        self.root = root
        # open allocation table
        fat_path = os.path.join(root, 'fat.json')
        if os.path.isfile(fat_path):
            with open(fat_path) as fat_file:
                self.fat = json.load(fat_file)
        else:
            self.fat = {
                '/': {
                    'meta': dict(
                        st_mode=(S_IFDIR | 0o755),
                        st_nlink=2,
                        st_ctime=datetime(2019,1,1).timestamp(),
                        st_mtime=datetime(2019,1,1).timestamp(),
                        st_atime=datetime(2019,1,1).timestamp(),
                    )
                },
            }
        self.open_files = self.fat

    def destroy(self, path):
        fat_path = os.path.join(self.root, 'fat.json')
        with open(fat_path, 'w') as fat_file:
            for f in self.fat:
                self.fat[f]['data'] = None
            json.dump(self.fat, fat_file)

    # Filesystem methods
    # ==================
#   @debug
#   def access(self, path, mode):
#       raise FuseOSError(errno.EACCES)

#   @debug
#   def chmod(self, path, mode):
#       pass

#   @debug
#   def chown(self, path, uid, gid):
#       pass

    @debug
    def getattr(self, path, fh=None):
        if path not in self.fat:
            raise FuseOSError(errno.ENOENT)
        return self.fat[path]['meta']

    @debug
    def readdir(self, path, fh):
        yield '.'
        yield '..'
        for ff in (k[1:] for k in self.fat.keys() if k != '/'):
            yield ff

#   @debug
#   def readlink(self, path):
#       pass
#       
#   @debug
#   def mknod(self, path, mode, dev):
#       pass

#   @debug
#   def rmdir(self, path):
#       pass

#   @debug
#   def mkdir(self, path, mode):
#       pass

#   @debug
#   def statfs(self, path):
#       pass

    @debug
    def unlink(self, path):
        del self.fat[path]
 
#   @debug
#   def symlink(self, name, target):
#       pass

    @debug
    def rename(self, old, new):
        pass

#   @debug
#   def link(self, target, name):
#       pass

#   @debug
#   def utimens(self, path, times=None):
#       pass

#   # File methods
#   # ============

    @debug
    def open(self, path, flags):
        self.open_files[path] = self.fat[path]
        return 1

    @debug
    def create(self, path, mode, fi=None):
        self.open_files[path] = {
            'data': b'',
            'meta': dict(
                st_mode=(S_IFREG | mode),
                st_nlink=1,
                st_size=0,
                st_ctime=time(),
                st_mtime=time(),
                st_atime=time()
            ),
            'chunks': [],
            'key': os.urandom(32).hex(),
        }
        return 1

    @debug
    def read(self, path, length, offset, fh):
        if not self.fat[path].get('data'):
            self.fat[path]['data'] = _read_chunks([os.path.join(self.root, chunk_hash) for chunk_hash in self.fat[path]['chunks']], bytes.fromhex(self.fat[path]['key']))
        return self.fat[path]['data'][offset:offset+length]


    def _encrypt_and_write_chunk(self, path, chunk):
        backend = default_backend()
        key = bytes.fromhex(self.fat[path]['key'])
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
        chunk_hash = hashlib.sha1(encrypted_chunk).hexdigest()
        with open(os.path.join(self.root, chunk_hash), 'wb') as cf:
            cf.write(iv)
            cf.write(encrypted_chunk)
        return chunk_hash


    @debug
    def _write_complete_chunks(self, path):
        # lets ignore updates
        chunk_size = 512
        file_dict = self.open_files[path]
        cc = len(file_dict['data'])//chunk_size
        chunks = file_dict.get('chunks', [])
        for i in range(len(chunks), cc):
            chunk_data = file_dict['data'][i*chunk_size:i*chunk_size+chunk_size]
            chunk_hash = self._encrypt_and_write_chunk(path, chunk_data)
            #hashlib.sha1(chunk_data).hexdigest()
            #with open(os.path.join(self.root, chunk_hash), 'wb') as cf:
            #    cf.write(chunk_data)
            chunks += [chunk_hash]
        file_dict['chunks'] = chunks

    def _flush_chunks(self, path):
        """ write last chunk to file padded with zeros """
        chunk_size = 512
        self._write_complete_chunks(path)
        file_dict = self.open_files[path]
        chunks = file_dict['chunks']
        last_chunk = file_dict['data'][len(chunks)*chunk_size:].ljust(chunk_size, '\x00'.encode('utf-8'))
        chunk_hash = self._encrypt_and_write_chunk(path, last_chunk)
        #chunk_hash = hashlib.sha1(last_chunk).hexdigest()
        #with open(os.path.join(self.root, chunk_hash), 'wb') as cf:
        #    cf.write(last_chunk)
        chunks += [chunk_hash]

    @debug
    def write(self, path, buf, offset, fh):
        file_dict = self.open_files[path]
        file_dict['data'] = \
            file_dict['data'][:offset].ljust(offset, '\x00'.encode('utf-8')) \
            + buf \
            + file_dict['data'][offset+len(buf):]
        file_dict['meta']['st_size'] = len(file_dict['data'])
        # TODO need to indicate if we're overwriting existing chunks!
        self._write_complete_chunks(path)
        return len(buf)

#   @debug
#   def truncate(self, path, length, fh=None):
#       pass

    @debug
    def flush(self, path, fh):
        pass

    @debug
    def release(self, path, fh):
        if self.fat[path].get('data'):
            self._flush_chunks(path)
        self.fat[path] = self.open_files[path]
        #del self.open_files[path]
        return

    @debug
    def fsync(self, path, fdatasync, fh):
        pass


def main(mountpoint, store):
    FUSE(Passthrough(store), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
