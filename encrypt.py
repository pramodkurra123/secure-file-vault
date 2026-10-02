from security import encrypt_file

encrypt_file(
    "protected_files/secret.txt",
    "protected_files/secret.enc"
)

print("File encrypted successfully.")