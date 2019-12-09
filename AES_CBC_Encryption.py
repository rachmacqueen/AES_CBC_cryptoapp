# Name: Rachel Sanders
# This application was created as an assignment for the Cryptographic Concepts unit, as part of Edith Cowan University's Y89 Bachelor of Science (Cyber Security)
# Python 3.6.5 was used for this assignment

# Import the required modules
import sys                                                                              #allows for stopping code execution
import os                                                                               #allows for more secure random number generation
import string                                                                           #allows for string operations
import random                                                                           #allows for random number generation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes            #allows the use of the ciphers, algorithms and modes for encrypting and decrypting data
from cryptography.hazmat.backends import default_backend                                #allows the use of the default backend instance, which is a required variable in creating a cipher object




#This function encrypts a block of plaintext input from the user, using AES-256-CBC encryption and returns the resulting ciphertext.
def encrypt(passphrase, message):
        #generate random iv
        backend = default_backend()
        iv = os.urandom(16)
        key = passphrase.encode('utf-8')          #256-bit key (8 * 32 bytes) guaranteed through random generator or forced user input
        en_plaintext = message.encode('utf-8')        #encoding allows us to work in bytes as opposed to a string
        
        #pad message to reach a multiple of 16
        pad_char = os.urandom(1)
        padsize = 16 - (len(en_plaintext) % 16)                 #(Sanfilippo, S., 2014. 'How to make sure the input is a multiple of 16, and if not add padding to it'. StackOverflow. Retrieved from https://stackoverflow.com/questions/21357437/how-to-make-sure-the-input-is-a-multiple-of-16-and-if-not-add-padding-to-it)
        if (len(en_plaintext) % 16) > 0:
            pad_text = en_plaintext + (pad_char * padsize)
        else:
            pad_text = en_plaintext
        
        #generate a AES-CBC cipher with the key and random iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)        #(Indiviual contributors., 2017. 'Symmetric Encryption'. https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(pad_text) + encryptor.finalize()
        
        #concatenate the iv and pad character to the end of the encrypted text
        cipher_iv_pad = ciphertext + iv + pad_char
                
        #return the ciphertext in hexadecimal format for easier storage in a .txt file
        hexcipher = (bytearray(cipher_iv_pad)).hex()
        return hexcipher

#This function decrypts a block of ciphertext using AES-256-CBC decryption and returns the resutlting plaintext.
def decrypt(keyphrase, encrypted_file):
        backend = default_backend()
        key = keyphrase.encode('utf')    
        
        #retrieve the ciphertext from hexadecimal format
        ciphertext = bytes.fromhex(encrypted_file)
        
        #strip the iv and the pad character from the end of the encrypted text
        iv = ciphertext[-17:-1]
        pad_char = ciphertext[-1:]
        
        #decrypt the original ciphertext (minus the iv and pad character) using the same AES-CBC cipher, the user input key and the extracted iv
        ciphertext = ciphertext[:-17]
        
        while True:                             #exception deals with the incorrect key input and will prompt until the correct key is entered
            try:
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
                break
            except ValueError:
                key = userInput('\nThe incorrect key was entered. Please enter the correct key: ')
                key = key.encode('utf-8')
                continue
            
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        #strip the padding from the plaintext
        pad_count = plaintext.count(b''+pad_char)       #(Ball, M., 2012. 'How to use count for bytearray'. StackOverflow. Retrieved from https://stackoverflow.com/questions/9214220/how-to-use-count-for-bytearray)
        if pad_count < 1:
                unpad_text = plaintext
        else:
                unpad_text = plaintext[:-pad_count]
        
        #decode the original plaintext               
        plaintext = unpad_text.decode('utf-8')

        return plaintext



# This function opens an user input filename.txt document in write mode and writes the data to it.
def saveFile(filename):                             #(Sweigart, A., 2013. 'Hacking Secret Ciphers with Python'. Chapter 11. Retrieved from https://inventwithpython.com/hacking/chapter11.html)
    if os.path.exists(filename+'.txt'):
        print('This file already exists. If you continue, you will overwrite the existing file. Do you wish to continue? [y]/[n]')
        choice = input('> ')
        while True:
            if choice.lower() == 'y':
                break;
            else:
                filename = userInput('\nPlease enter a different filename for your encrypted message: \n')
                with open(filename+'.txt', 'w') as w:
                    w.write(hexcipher)
                    w.close()
                    return
                
    with open(filename+'.txt', 'w') as f:
        f.write(hexcipher)
        f.close()
        return

       
#This function repeatedly prompts for input until something (not whitespace) is entered.
def userInput(prompt):
    while True:
        value = input(prompt).strip()      
        if len(value) >= 1:
            return value
            break;
        else:
            print('\nAn input is required - Please try again. \n')
            continue

#This function prompts the user for input of a length of 32 bytes, and prompts user for different input if it does not match 32 bytes.
def inputKey(prompt):
    while True:
        value = input(prompt).strip()
        encoded_key = value.encode('utf-8')
        key_length = len(encoded_key)
        if key_length == 32:
            return value #not sure if encoded key is needed yet
            break;
        else:
            print('\nYour key length is: '+str(key_length))    
            print('The key must have a length of 32 bytes - Please try again. \n')
            continue

#This function generates a random 32 byte key.
def randomKey(size=32, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):  #(Vazquez-Abrams, I., 2010. 'Random string generation with upper case letters and digits in Python'. StackOverflow. Retrieved from https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python)
    random_key = ''.join(random.SystemRandom().choice(chars) for _ in range(size))
    return random_key

        
        
    
        

#start of program
while True:
        print('\nWelcome to this Cryptographic Application! This application uses AES-256-CBC symmetric encryption to provide secure communication. ')
        while True:
            print('\nPlease press [e] to begin encrypting a new message, [d] to decrypt an existing message, or [q] to quit.')
            choice = input('> ')

            if choice.lower() == 'e':        
                while True:
                    print('\nChoose [k] to enter a 32-byte key of your choice, [r] to randomly generate a 32-bit key or [q] to quit to the menu.')
                    choice = input('> ')
                    if choice.lower() == 'k': #Allows the user to manually enter a key
                        passphrase = inputKey('Please enter your key, then press enter: ')
                        print('Your key has been saved. Do you wish to view your key? [y]/[n]')
                        choice = input('> ')
                        if choice.lower() == 'y':
                            print('Your key is: ', passphrase, '. Please copy this key and store it in a safe place. \n')
                            break
                        else:
                            print('If you do not share your key with the recipient of your message, they cannot decrypt it. Are you sure you want to continue without saving your key? [y]/[n]')
                            choice = input('> ')
                            if not choice.lower() == 'y':
                                print('Your key is: ', passphrase, '. Please copy this key and store it in a safe place. \n')
                                break
                      
                                    
                    elif choice.lower() == 'r': #Allows the user to randomly generate a key
                        passphrase = randomKey()
                        print('Your random key has been generated. Do you wish to view your key? [y]/[n]')
                        choice = input('> ')
                        if choice.lower() == 'y':
                            print('Your key is: ', passphrase, ' Please copy this key and store it in a safe place. \n')
                            break
                        else:
                            print('If you do not share your key with the recipient of your message, they cannot decrypt it. Are you sure you want to continue without saving your key? [y]/[n]')
                            choice = input('> ')
                            if not choice.lower() == 'y':
                                print('Your key is: ', passphrase, '. Please copy this key and store it in a safe place. \n')
                                break
                                                
                    elif choice.lower() == 'q':
                        break;

                    else:
                        print('Invalid choice. Please choose one of the given options.')
                        continue

                
                while True:
                    message = userInput('Please type the message you wish to encrypt: ')
                    print('\nTo view your message, press [v]. To enter a different message, please press [e], or press any key to continue.')
                    choice = input('> ')
                    if choice.lower() == 'e':
                        continue           
                    elif choice.lower() == 'v':
                        print('This is the message you wish to encrypt:\n'+'\n'+message)
                        print('\n To enter a different message, please press [e], or press any key to continue.')
                        choice = input('> ')
                        if choice.lower() == 'e':
                            continue
                        else:
                            break
                    else:
                            break
          
                print('\nPlease wait while your message is encrypted...\n')
                hexcipher = encrypt(passphrase, message)
                
                while True:
                    filename = userInput('Please enter a filename for your encrypted message: ')
                    print('\nTo enter a different filename, please press [e], or press any key to continue.')
                    choice = input('> ')
                    if choice.lower() == 'e':
                        continue           
                    else:
                        encrypted_file = saveFile(filename)
                        print('Your encrypted file has been saved.')
                        break        

                
            elif choice.lower() == 'd':
                print('\nTo return to the main menu, press [q], or press any key to continue.')
                choice = input('> ')
                if choice.lower() == 'q':
                        break
                else:
                        while True:
                            en_filename = userInput('\nPlease enter the name of the file you wish to decrypt: ')
                            if not os.path.exists(en_filename+'.txt'):
                                print('That file does not exist. Please try again.')
                                continue
                            else:
                                print('The file has been located. Extracting information now.\n')
                                ef = open(en_filename+'.txt', 'r')
                                encrypted_file = ef.read()
                                try:                            #exception deals with files that do not contain hex data and therefore cannot be decrypted
                                        hex_check = bytes.fromhex(encrypted_file)
                                        break
                                except ValueError:
                                        print('This file contains an invalid data type and cannot be decrypted. Please try again.')
                                        continue
                                
              
                keyphrase = userInput('Please enter the key: ')
                plaintext = decrypt(keyphrase, encrypted_file)
                print('\nThe decrypted message is: '+plaintext)

            elif choice.lower() == 'q':
                print('\nFarewell!\n')
                sys.exit()
                            
            else:
                print('Invalid choice. Please choose one of the given options.')
                continue































        
