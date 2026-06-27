import io
import os
import paramiko

REMOTE_DIR = "/usr/home/cig7qy/public_html"
LOCAL_DIR = "public"

key = paramiko.Ed25519Key.from_private_key(io.StringIO(os.environ["SFTP_KEY"]))
transport = paramiko.Transport((os.environ["SFTP_HOST"], 22))
transport.connect(username=os.environ["SFTP_USER"], pkey=key)
sftp = paramiko.SFTPClient.from_transport(transport)

for root, _, files in os.walk(LOCAL_DIR):
    rel = os.path.relpath(root, LOCAL_DIR)
    remote_subdir = REMOTE_DIR if rel == "." else REMOTE_DIR + "/" + rel.replace(os.sep, "/")
    if rel != ".":
        try:
            sftp.stat(remote_subdir)
        except FileNotFoundError:
            sftp.mkdir(remote_subdir)
    for name in files:
        local_path = os.path.join(root, name)
        remote_path = remote_subdir + "/" + name
        print(f"uploading {remote_path}")
        sftp.put(local_path, remote_path)

sftp.close()
transport.close()
print("Deploy complete.")
