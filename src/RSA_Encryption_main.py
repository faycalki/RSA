# sys module to better organize the module directory

from Modules import license_input

#   Purpose and version of program
__purpose__ = "This RSA Encryption and Decryption program allows you to encrypt or decrypt files and messages, with optimal parameters to go above and beyond the encryption capabilities of most encryption programs."
__version__ = "Program Version: 1.0"

#   License and Author
__author__ = "Faycal Kilali"
__copyright__ = "Copyright (C) 2021 Faycal Kilali"
__license__ = "GNU GENERAL PUBLIC LICENSE"
__license_version__ = "3.0"

#   Display purpose and version, license and version of license.
print(__purpose__, "\n", __version__)
print(__copyright__, "\n", __license__, __license_version__, "\n")

# License disclaimer and extra details input
license_input.reveal_license_options()

import RSA_Encryption_backend

# Fast processing settings (not secure, edit them to be secure, the higher the coprimes_to_check_against the more likely the primes are in fact prime, the higher slicer_value is the less secure the encryption is)
coprimes_to_check_against = 5
slicer_value = 100
unicode_numeral = 1


def operate(coprimes_to_check_against, slicer_value):
    file_name = "placeholder"
    list_of_primes = []
    debug = input("If you wish to enable debug mode input 1, otherwise hit enter: ")
    if debug == "1":
        debug = 1
    else:
        debug = 0
    # unicode_numeral = input(
    #    "if what you want to encrypt is already in the form of unicode numerals input 0, otherwise hit enter: "
    # )
    # if unicode_numeral == "0":
    #    unicode_numeral = 0
    # else:
    #    unicode_numeral = 1
    choose_type_of_input = input(
        "To encrypt a file input 1.\nTo encrypt a message input 2\nTo decrypt a file input 3\nTo decrypt a message input 4.\nInput: "
    )
    if choose_type_of_input != "1" and choose_type_of_input != "2":
        if choose_type_of_input != "3" and choose_type_of_input != "4":
            operate(coprimes_to_check_against, slicer_value)
        else:
            if choose_type_of_input == "3":
                choose_program = "d"
                choose_type_of_input = "1"
            elif choose_type_of_input == "4":
                choose_program = "d"
                choose_type_of_input == ""
    elif choose_type_of_input == "1":
        choose_program = "e"
    elif choose_type_of_input == "2":
        choose_program = "e"
    else:
        operate(coprimes_to_check_against, slicer_value)

    # choose_program = input("Input e for the encoder or d for the decoder: ")
    #
    # choose_type_of_input = input(
    #    "If you wish to encrypt or decrypt a file input 1, if you wish to encrypt or decrypt a string instead (message), press enter: "
    # )
    # choose_program = input("Input e for the encoder or d for the decoder: ")

    if choose_program == "e":
        primes_upper_bound_string = input(
            "Input the maximum integer value the primes can be (Inputting a value of 200 digits would make the encryption extremely secure but would take a very long time, recommending a size 5 digits for demonstration purposes, so 10000 should work well): "
        )
        try:
            primes_upper_bound = int(primes_upper_bound_string)
        except ValueError:
            print("Plug in an integer value next time.")
            operate(coprimes_to_check_against, slicer_value)
        if primes_upper_bound < 1000:
            print("Plug in an integer value of at least 10000 (5 digits)!")
        else:
            if primes_upper_bound % 2 == 0:
                primes_lower_bound = (primes_upper_bound // 10) - 997
            else:
                primes_lower_bound = primes_upper_bound - 998

            # Generating keys, this can be called outside the function modularly. Returns the public keys (N, e), and private keys (list_of_primes)
            # Arguments: lowest prime boundary, highest prime boundary, number of coprimes to check against the primes, slicer value, debug enabled (1 on, 0 off)
            N, e, list_of_primes = RSA_Encryption_backend.generate_keys(
                primes_lower_bound,
                primes_upper_bound,
                coprimes_to_check_against,
                slicer_value,
                debug,
            )
            # Taking user input and converting it into a string.
            if choose_type_of_input == "1":
                file_name = input(
                    "Input the full name of the file with its extension to encrypt (in the same directory as this python script): "
                )
                try:
                    with open(file_name, "r") as file:
                        string_to_be_encoded = file.read()
                        file.close()
                except FileNotFoundError:
                    print(
                        "File not found, make sure you write the exact name, including the extension of the file you'd like to encrypt or decrypt."
                    )
                    operate(coprimes_to_check_against, slicer_value)
            else:
                string_to_be_encoded = input(
                    "Input the message you wish to be encrypted: "
                )

            unencrypted_string = (
                string_to_be_encoded  # Used to summarize the unencrypted content
            )

            # Converting user input into unicode numerals (you may use whatever other method you wish instead, as long as it gives a numeral representation). Returns the string_to_be_encoded in joined unicode numerals form, as well as unicode_of_string which is string_to_be_encoded in unicode numerals but not joined.
            # Arguments: string, debug enabled (1 on, 0 off)
            if unicode_numeral == 1:
                (
                    string_to_be_encoded,
                    unicode_of_string,
                    unicode_of_string_length,
                ) = RSA_Encryption_backend.unicode_numeral(string_to_be_encoded, debug)
            # Encoding the string, returns encoded_message.
            # Arguments: numeral_string, N, E, debug enabled (1 on, 0 off)
            encoded_message = RSA_Encryption_backend.encoder(
                string_to_be_encoded, N, e, debug
            )

            # Acquiring the decryption key, returns decoder_key and decoded_list
            # Arguments: N, e, decryption key (options: decryption key (if you have it), "generate_decryption_key" string to generate a decryption key based on the rest of the arguments, or leave blank in order to attempt to decrypt the file based on the given arguments), encrypted message, unicode_numeral, list_of_primes (optional, only required if generating your own decryption keys, however this argument must be passed regardless -- so use an empty list if necessary)
            decoder_key = "generate_decryption_key"
            decoder_key = RSA_Encryption_backend.decoder(
                N,
                e,
                decoder_key,
                encoded_message,
                list_of_primes,
                debug,
            )

            # Writing the public keys, private keys, encoded message and decoded message to the client's current executable directory.
            # Arguments: public keys, private keys, unencrypted message, encoded message, N, e, list of primes (the list the private keys are acquired from), type of unencrypted message (1 for unicode numeral, 0 for every other type of numeral), debug (1 for on, 0 for off), unicode_of_string which is the second part returned from unicode_numeral function, is_file which tells the write_to_file whether its a file or not -- makes it so that it writes the encrypted file with __encrypted appended and doesn't write the content of the file to keys.txt, file_name gives the name of the file, choose_program (which is the chosen encoder or decoder program), decoder_key which is the decryption key.
            public_keys = (N, e)
            __private_keys = (list_of_primes[0], list_of_primes[1])
            RSA_Encryption_backend.write_to_file(
                public_keys,
                __private_keys,
                unencrypted_string,
                encoded_message,
                N,
                e,
                list_of_primes,
                unicode_numeral,
                debug,
                unicode_of_string,
                choose_type_of_input,
                file_name,
                choose_program,
                decoder_key,
                unicode_of_string_length,
            )
    # joined_unicode_of_string
    elif choose_program == "d":
        if choose_type_of_input == "1":
            file_name = input(
                "Input the full name of the file with its extension to decrypt (in the same directory as this python script): "
            )
            try:
                with open(file_name, "r") as file:
                    encoded_message = file.read()
                    file.close()
            except FileNotFoundError:
                print(
                    "File not found, make sure you write the exact name, including the extension of the file you'd like to encrypt or decrypt."
                )
                operate(coprimes_to_check_against, slicer_value)
        else:
            encoded_message = input(
                "Input the encoded message you'd like to decrypt, make sure it is exactly the encoded message with no additional spaces or blank lines: "
            )
        N = input("Input the first part of the public key, that is N: ")
        try:
            N = int(N)
        except ValueError:
            print("Plug in an integer value next time.")
            operate(coprimes_to_check_against, slicer_value)
        e = input("Input the second part of the public key, that is e: ")
        try:
            e = int(e)
        except ValueError:
            print("Plug in an integer value next time.")
            operate(coprimes_to_check_against, slicer_value)
        decoder_key = input(
            "Input the decryption key, make sure there are no spaces and no number is missing from it: "
        )
        try:
            decoder_key = int(decoder_key)
        except ValueError:
            print("Plug in an integer value next time.")
            operate(coprimes_to_check_against, slicer_value)
        unicode_of_string_length = input(
            "Input the unicode decoder list, make sure it is exactly as provided in the keys.txt file: "
        )

        decoded_list = RSA_Encryption_backend.decoder(
            N,
            e,
            decoder_key,
            encoded_message,
            list_of_primes,
            debug,
        )

        # Take the decoded list to the inverse thing...

        # Return the proper file.

        #   Placeholders until I figure out how to pass optional arguments instead of mandatory
        unencrypted_string = "placeholder"
        __private_keys = "placeholder"
        unicode_of_string = decoded_list
        print(decoded_list)

        # Writing the public keys, private keys, encoded message and decoded message to the client's current executable directory.
        # Arguments: public keys, private keys, unencrypted message, encoded message, N, e, list of primes (the list the private keys are acquired from), type of unencrypted message (1 for unicode numeral, 0 for every other type of numeral), debug (1 for on, 0 for off), unicode_of_string which is the second part returned from unicode_numeral function, is_file which tells the write_to_file whether its a file or not -- makes it so that it writes the encrypted file with __encrypted appended and doesn't write the content of the file to keys.txt, file_name gives the name of the file, choose_program (which is the chosen encoder or decoder program), decoder_key which is the decryption key.
        public_keys = (N, e)
        RSA_Encryption_backend.write_to_file(
            public_keys,
            __private_keys,
            unencrypted_string,
            encoded_message,
            N,
            e,
            list_of_primes,
            unicode_numeral,
            debug,
            unicode_of_string,
            choose_type_of_input,
            file_name,
            choose_program,
            decoder_key,
            unicode_of_string_length,
        )

    operate(coprimes_to_check_against, slicer_value)


operate(coprimes_to_check_against, slicer_value)