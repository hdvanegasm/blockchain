import os
import shutil

"""
Source code from: https://stackoverflow.com/questions/185936/how-to-delete-the-contents-of-a-folder
"""


def delete_files_folder(folder):
    print("==> Deleting files from", folder)
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


if __name__ == "__main__":
    delete_files_folder("../private_keys/")
    delete_files_folder("../public_keys/")
