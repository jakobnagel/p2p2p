from os import listdir, getcwd
from os.path import isfile, join
import random

def complete_file_download(fname, fdata):
    full_fpath = join(join(getcwd(), "files"), fname)
    if isfile(full_fpath):
        new_fname = str(random.randint(0,100000)) + fname
        print(f"File {fname} already exists. Saving new file as {new_fname}")
        complete_file_download(new_fname, fdata)
    else:
        with open(full_fpath, 'wb') as f:
            f.write(fdata)
        print(f"File {fname} saved.\n")
