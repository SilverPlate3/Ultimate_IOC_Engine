from hashlib import sha256
import easygui


def get_file():
    return easygui.fileopenbox()


def hash_a_file():
    with open(get_file(), 'rb') as f:
        file_bytes = f.read()
        file_sha256 = sha256(file_bytes).hexdigest()

    return file_sha256



