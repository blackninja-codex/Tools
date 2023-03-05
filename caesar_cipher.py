def encrypt_plaintext(plaintext,n):
    ans = ""
    # iterate over the given text
    for i in range(len(plaintext)):
        ch = plaintext[i]
        # check if space is there then simply add space
        if ch==" ":
            ans+=" "
        # check if a character is uppercase then encrypt it accordingly 
        elif (ch.isupper()):
            ans += chr((ord(ch) + n-65) % 26 + 65)
        # check if a character is lowercase then encrypt it accordingly
        else:
            ans += chr((ord(ch) + n-97) % 26 + 97)
    return ans

def decrypt_ciphertext():    
    encrypted_message = input("Enter the message i.e to be decrypted: ").strip()    
    letters='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'    
    k = int(input("Enter the key to decrypt: "))
    decrypted_message = ""
    for ch in encrypted_message:
        if ch in letters:
            position = letters.find(ch)
            new_pos = (position - k) % 26
            new_char = letters[new_pos]
            decrypted_message += new_char
        else:
            decrypted_message += ch
    print("Your decrypted message is:\n")
    print(decrypted_message)

def bruteforce_ciphertext():
    ciphertext=input("Enter Ciphertext")
    message = ciphertext
    Letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for key in range(len(Letters)):
    translated = ''
    for ch in message:
        if ch in Letters:
            num = Letters.find(ch)
            num = num - key
            if num < 0:
            num = num + len(Letters)
            translated = translated + Letters[num]
        else:
            translated = translated + ch
    print('Hacking key is %s: %s' % (key, translated))

choice = input("Enter 1 to encrypt_plaintext or Enter 2 to decrypt_ciphertext or Enter 3 to bruteforce ciphertext")
if choice==1:
    plaintext = input("enter plaintext to encrpyt")
    key=input("enter key value")
    print("Plain Text is : " + plaintext)
    print("Shift pattern is : " + str(key))
    print("Cipher Text is : " + encrypt_text(plaintext,key))
if choice==2:
    decrypt_ciphertext()
if choice==3:
    bruteforce_ciphertext()



