from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from Crypto.IO import PEM, PKCS8
import os
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from . import settings
import base64
import hashlib
from django.contrib import messages
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_symmetric_key():
    # generamos clave de 256 bits para AES (32 bytes aleatorios)
    return get_random_bytes(32)

def generate_rsa_key_pair():
    # generamos clave RSA de 2048 bits
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()  
    return public_key, private_key

def import_rsa_key(key_data):
    try:
        return RSA.import_key(key_data)
    except ValueError as e:
        # Log this error appropriately or handle it as necessary
        raise ValueError(f"Error importing RSA key: {str(e)}")

def encrypt_symmetric_key(user_public_key, symmetric_key):
    if not isinstance(user_public_key, bytes):
        raise TypeError("Public key must be a byte string")
    if not isinstance(symmetric_key, bytes):
        raise TypeError("Symmetric key must be a byte string")
    public_key = import_rsa_key(user_public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    try:
        encrypted_key = cipher_rsa.encrypt(symmetric_key)
        return encrypted_key
    except Exception as e:
        # Handle or log the error properly
        raise RuntimeError(f"Failed to encrypt symmetric key: {str(e)}")


def decrypt_symmetric_key(user_private_key, encrypted_key):
    if not isinstance(user_private_key, bytes):
        raise TypeError("Private key must be a byte string")
    if not isinstance(encrypted_key, bytes):
        raise TypeError("Symmetric key must be a byte string")
    # Primero, decodifica la clave privada de bytes a una cadena de texto
    private_key = import_rsa_key(user_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    try:
        symmetric_key = cipher_rsa.decrypt(encrypted_key)
        return symmetric_key
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt symmetric key: {str(e)}")
    
# Función para cifrar un archivo con AES y una clave simétrica. Mode puede ser AES.MODE_CBC o AES.MODE_EAX, con CBC como modo predeterminado
def encrypt_file(file, symmetric_key, mode=AES.MODE_CBC): # mode es un parámetro opcional con valor predeterminado AES.MODE_CBC
    
    if mode == AES.MODE_CBC:
        # Genera un IV seguro para AES-CBC
        iv = Random.new().read(AES.block_size)
        # Crea una instancia de cifrador AES en modo CBC con la clave y el IV
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        # Leer el contenido del archivo
        file_content = file.read()
        # AES requiere que el tamaño del archivo sea un múltiplo de 16, por lo que se añade padding si es necesario
        padding_length = AES.block_size - len(file_content) % AES.block_size
        file_content += bytes([padding_length]) * padding_length
        # Cifra el contenido del archivo
        encrypted_content = iv + cipher.encrypt(file_content)
        # Devuelve el contenido cifrado, que será un archivo binario de tipo bytes
        return encrypted_content
    elif mode == AES.MODE_EAX:
        cipher = AES.new(symmetric_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(file.read())
        return cipher.nonce + tag + ciphertext
    else:
        raise ValueError("Invalid mode. Use AES.MODE_CBC or AES.MODE_EAX")


def decrypt_file(input_file_path, symmetric_key, mode=AES.MODE_CBC): # mode es un parámetro opcional con valor predeterminado AES.MODE_CBC
    ensure_uploads_folder_exists()
    with open(input_file_path, 'rb') as encrypted_file:
        if mode == AES.MODE_EAX:
            # Desencripta el archivo usando EAX
            nonce = encrypted_file.read(16)
            tag = encrypted_file.read(16)
            ciphertext = encrypted_file.read()
            cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
            decrypted_content = cipher.decrypt_and_verify(ciphertext, tag)
            # Devuelve el contenido descifrado
            return decrypted_content
        elif mode == AES.MODE_CBC:
            iv = encrypted_file.read(AES.block_size)
            cipher = AES.new(symmetric_key, AES.MODE_CBC, iv) # Crea un cifrador AES en modo CBC con la clave y el IV
            decrypted_content = cipher.decrypt(encrypted_file.read()) # Descifra el contenido del archivo
            padding_length = decrypted_content[-1] # El último byte indica la longitud del padding
            decrypted_content = decrypted_content[:-padding_length] # Elimina el padding
            decrypted_file_bytes = BytesIO(decrypted_content) # Crea un objeto BytesIO con el contenido descifrado
            # Obtenemos el nombre del archivo original, sin la ruta completa
            input_file_name = os.path.basename(input_file_path)[:-4] # Basename devuelve el último componente de la ruta, y eliminamos la extensión .enc
            decrypted_file = InMemoryUploadedFile(file=decrypted_file_bytes, name=input_file_name, field_name=input_file_name, content_type=None, size=len(decrypted_content), charset=None) # Crea un objeto InMemoryUploadedFile
            return decrypted_file

def get_user_private_key(user):
    filename = f'{user.username}_private_key.pem'
    file_path = os.path.join(settings.PRIVATE_KEY_FOLDER, filename)
    with open(file_path, 'rb') as file:
        encrypted_private_key = file.read()
    passphrase = settings.ADMIN_PRIVATE_KEY_PASSPHRASE.encode('utf-8')
    # Utilizamos PKCS8 para descifrar la clave privada.
    private_key = PKCS8.unwrap(encrypted_private_key, passphrase=passphrase)
    return private_key[1]


def get_user_public_key(user):
    public_key = user.public_key
    return public_key

def get_user_symmetric_key(user):
    key = user.group.group_members.get(user=user).encrypted_symmetric_key
    plaintext_key = decrypt_symmetric_key(get_user_private_key(user), key)
    return plaintext_key.encode('utf-8')

def get_file_hash(file):
    # Calcula el hash del archivo
    hasher = hashlib.sha256()
    # Lee el archivo en bloques de 4096 bytes, debido a que el archivo puede ser muy grande
    for chunk in file.chunks():
        hasher.update(chunk)
    # Devuelve el hash en formato hexadecimal
    return hasher.hexdigest()

def ensure_private_key_folder_exists():
    if not os.path.exists(settings.PRIVATE_KEY_FOLDER):
        os.makedirs(settings.PRIVATE_KEY_FOLDER)

def ensure_group_folder_exists(group):
    if not os.path.exists(os.path.join(settings.UPLOADS_DIR, f"group_{group.group_name}")):
        os.makedirs(os.path.join(settings.UPLOADS_DIR, f"group_{group.group_name}"))

def ensure_uploads_folder_exists():
    if not os.path.exists(settings.UPLOADS_DIR):
        os.makedirs(settings.UPLOADS_DIR)
# Función para obtener o generar la clave simétrica de un grupo
# Se puede usar para subir un archivo a un grupo, cifrarlo y guardarlo en la base de datos, o para descargar un archivo cifrado y descifrarlo
def get_or_generate_symmetric_key(group, user, create=False): # create es un parámetro opcional que indica si se debe crear una nueva clave simétrica
    if not get_user_public_key(user) or get_user_public_key(user) is None or create:
        user.public_key, private_key = generate_rsa_key_pair()
        ensure_private_key_folder_exists()
        user.private_key_path = save_private_key(user, private_key)
        user.save()
    # Si el usuario no puede acceder a la clave simétrica cifrada del grupo y debería tener acceso, la crea
    if (user == group.owner and not group.encrypted_symmetric_key) or (user == group.owner and create): # Si el usuario es el propietario del grupo y no hay clave simétrica cifrada en el grupo, o si es nula
        symmetric_key = generate_symmetric_key()
        encrypted_symmetric_key = encrypt_symmetric_key(user.public_key, symmetric_key)
        # decrypted_symmetric_key = decrypt_symmetric_key(user.public_key, private_key, encrypted_symmetric_key)
        group.encrypted_symmetric_key = encrypted_symmetric_key # encrypt_symmetric_key(group.owner.public_key, private_key, symmetric_key)
        group.save()
    elif user != group.owner:
        group_member = group.members.get(user=user)
        if (not group_member.encrypted_symmetric_key or group_member.encrypted_symmetric_key is None) and (not group.encrypted_symmetric_key or group.encrypted_symmetric_key is None) or create:
            symmetric_key = generate_symmetric_key()
            encrypted_symmetric_key = encrypt_symmetric_key(user.public_key, symmetric_key)
            group.encrypted_symmetric_key = encrypt_symmetric_key(group.owner.public_key, symmetric_key)
            group_member.encrypted_symmetric_key = encrypted_symmetric_key
            group_member.save()
            group.save()
        elif (not group_member.encrypted_symmetric_key or group_member.encrypted_symmetric_key is None) and group.encrypted_symmetric_key is not None:
            symmetric_key = decrypt_symmetric_key(private_key, group.encrypted_symmetric_key)
            group_member.encrypted_symmetric_key = encrypt_symmetric_key(user.public_key, symmetric_key)
            group_member.save()
    private_key = get_user_private_key(user)
    if user == group.owner:
        encrypted_symmetric_key = group.encrypted_symmetric_key
        return decrypt_symmetric_key(private_key, encrypted_symmetric_key)
    else:
        encrypted_symmetric_key = group.members.get(user=user).encrypted_symmetric_key
        return decrypt_symmetric_key(private_key, encrypted_symmetric_key)

def decrypt_group_symmetric_key(group, user):
    encrypted_key = get_or_generate_symmetric_key(group, user)
    return decrypt_symmetric_key(get_user_private_key(user), encrypted_key)

# Guarda el archivo cifrado en la base de datos: para ello creamos un archivo nuevo para los datos cifrados y eliminamos el archivo original
def save_private_key(user, private_key):
    # Asegúrate de que la clave privada ya esté en formato binario PEM.
    # No es necesario decodificar a utf-8 ya que PEM.export_key() retorna bytes.
    if not os.path.exists(settings.PRIVATE_KEY_FOLDER):
        os.makedirs(settings.PRIVATE_KEY_FOLDER)
    filename = f'{user.username}_private_key.pem'
    file_path = os.path.join(settings.PRIVATE_KEY_FOLDER, filename)
    # Aseguramos que la passphrase sea adecuada para el cifrado.
    passphrase = settings.ADMIN_PRIVATE_KEY_PASSPHRASE.encode('utf-8')
    rsa_oid = '1.2.840.113549.1.1.1'  # OID para RSA
    # Usamos PKCS8 para el almacenamiento seguro de claves privadas con passphrase.
    encrypted_private_key = PKCS8.wrap(private_key, passphrase=passphrase, key_oid=rsa_oid,protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC')
    with open(file_path, 'wb') as file:
        file.write(encrypted_private_key)
    return file_path

def generate_signature(private_key, file_data):
    hash_obj = SHA256.new(file_data)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hash_obj)
    return signature

def verify_signature(public_key, file_data, signature):
    hash_obj = SHA256.new(file_data)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def save_encrypted_file(file_instance, group, user):
    ensure_uploads_folder_exists()
    ensure_group_folder_exists(group)
    
    encrypted_file_data = encrypt_file(file_instance.file, get_or_generate_symmetric_key(group, user, create=False))
    encrypted_file_path = os.path.join(settings.UPLOADS_DIR,  f"group_{group.group_name}",f"{file_instance.file_name}.enc")
    
    # Simulamos la creación de un objeto InMemoryUploadedFile
    encrypted_file_bytes = BytesIO(encrypted_file_data)

    # InMemoryUploadedFile(file, field_name, name, content_type, size, charset, content_type_extra)
    encrypted_file = InMemoryUploadedFile(
        file=encrypted_file_bytes,
        name=f"{file_instance.file_name}.enc", 
        field_name=f"{file_instance.file_name}.enc", 
        content_type=None, 
        # Primer cambio: el tamaño del archivo cifrado es el tamaño de los bytes del archivo cifrado
        size=encrypted_file_bytes.getbuffer().nbytes,
        charset=None
    )
    return encrypted_file, encrypted_file_path

"""
def get_or_generate_symmetric_key(group, user, create=False): # create es un parámetro opcional que indica si se debe crear una nueva clave simétrica
    if not get_user_public_key(user) or get_user_public_key(user) is None or create:
        user.public_key, private_key = generate_rsa_key_pair()
        # user.public_key es de tipo bytes, por lo que se convierte a cadena de texto
        user.save()
        if not os.path.exists(settings.PRIVATE_KEY_FOLDER):
            os.makedirs(settings.PRIVATE_KEY_FOLDER)
            messages.info("La carpeta de claves privadas no existe, se ha creado.")
        save_private_key(user, private_key)
        if (user == group.owner and not group.encrypted_symmetric_key) or create: # Si el usuario es el propietario del grupo y no hay clave simétrica cifrada en el grupo, o si es nula
            group.encrypted_symmetric_key = encrypt_symmetric_key(group.owner, generate_symmetric_key())
            group.save()
        else:
            group_member = group.members.get(user=user)
            group_member.encrypted_symmetric_key = encrypt_symmetric_key(user, generate_symmetric_key())
    # private_key = get_user_private_key(user)
    # public_key = get_user_public_key(user)
    if user == group.owner:
        return decrypt_symmetric_key(user, group.encrypted_symmetric_key)
    else:
        return decrypt_symmetric_key(user, group.members.get(user=user).encrypted_symmetric_key)
"""

"""
def get_or_generate_symmetric_key(group, user, create=False): # create es un parámetro opcional que indica si se debe crear una nueva clave simétrica
    if not group.encrypted_symmetric_key or group.encrypted_symmetric_key is None or create: # Si no hay clave simétrica cifrada en el grupo, o si es nula
        if not get_user_public_key(group.owner) or get_user_public_key(group.owner) is None or create:
            group.owner.public_key, private_key = generate_rsa_key_pair()
            group.owner.save()
            save_private_key(group.owner, private_key)
        group.encrypted_symmetric_key = encrypt_symmetric_key(group.owner.public_key, generate_symmetric_key())
        group.save()
    if not os.path.exists(settings.PRIVATE_KEY_FOLDER):
        os.makedirs(settings.PRIVATE_KEY_FOLDER)
        messages.info("La carpeta de claves privadas no existe, se ha creado.")
    private_key = get_user_private_key(user)
    return decrypt_symmetric_key(public_key, private_key, group.encrypted_symmetric_key)
"""

# Guarda el archivo cifrado en el sistema de archivos
    # with open(encrypted_file_path, 'wb') as encrypted_file:
    #     encrypted_file.write(encrypted_file_data)
