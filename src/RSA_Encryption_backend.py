from Modules import (
    primality_tester_modular,
)  # Function: primality_tester, arguments: detail, prime_number_to_check, coprimes_to_check_against
from Modules import (
    euclidean_algorithm_for_two_or_more_numbers_modular,
)  # Function: modular_euclidean_algorithm, arguments: discrete number of integers to check the hcf of, 1, first_factor_value, second_factor_value
import random

unicode_of_string = []
unicode_of_string_inverse = []
unicode_of_encoded_string = []


def generate_keys(
    primes_lower_bound,
    primes_upper_bound,
    coprime_integers_to_check_against,
    slicer,
    debug,
):
    list_of_primes = []

    def generate_odd_positive_integers(primes_upper_bound, primes_lower_bound):
        candidate_of_certain_digits = random.randrange(
            primes_lower_bound, primes_upper_bound, 2
        )
        if debug == 1:
            print("DEBUG: Integer we are checking is %d" % candidate_of_certain_digits)
        check_if_prime(candidate_of_certain_digits)

    def check_if_prime(candidate):
        if (
            primality_tester_modular.primality_tester(
                "-1", candidate, coprime_integers_to_check_against
            )
            == "is prime"
        ):
            list_of_primes.append(candidate)
        else:
            generate_odd_positive_integers(primes_upper_bound, primes_lower_bound)

    # Populate list with two primes, we call the function twice.
    max_length = 2
    for i in range(0, max_length):
        generate_odd_positive_integers(primes_upper_bound, primes_lower_bound)
        if i > 1:
            if list_of_primes[0] == list_of_primes[1]:
                list_of_primes[1].pop
                max_length += 1

    # Just for checking (for now), we check the list of primes:
    if debug == 1:
        print("DEBUG: The primes found are: %s" % list_of_primes)

    # Assigning pq
    if len(list_of_primes) == 2:
        N = list_of_primes[0] * list_of_primes[1]

    # Function to choose a large number e, not necessarily the largest, in this case we divide by 2 to get a large one but its just designers choice in this case.
    # The higher the value of the slicer is, the faster it is to encode and decode, but potentially less secure. Although a minimum value of 2 is required, since 1 is likely unsecure for none-computers.

    def find_coprime(prime_1, prime_2, slicer):
        for coprime_search in range(((prime_1 - 1) * (prime_2 - 1)) // slicer, 2, -1):
            (
                hcf_and_lcm_list
            ) = euclidean_algorithm_for_two_or_more_numbers_modular.modular_euclidean_algorithm(
                2, 1, (prime_1 - 1) * (prime_2 - 1), coprime_search
            )
            if hcf_and_lcm_list[0] == 1:
                if debug == 1:
                    print("Value of the coprime e: %s" % coprime_search)
                return coprime_search
            else:
                hcf_and_lcm_list.pop(0)
                hcf_and_lcm_list.pop(0)

    return N, find_coprime(list_of_primes[0], list_of_primes[1], slicer), list_of_primes


def unicode_numeral(string, debug):
    # This function converts symbols to their ordinal value for encryption and decryption purposes, useful if you don't plan on using another method of numeral representation of symbols.
    unicode_of_string = []
    for character in string:
        number_of_char = ord(character)
        unicode_of_string.append(number_of_char)
    if debug == 1:
        print(
            "DEBUG: Unicode numeral representation of all the string characters is: %s"
            % unicode_of_string
        )
    joining_unicode_of_string = [str(int) for int in unicode_of_string]
    return "".join(joining_unicode_of_string), unicode_of_string


def inverse_unicode_numeral(string, debug):
    # This function deconverts from Unicode Numerals
    if debug == 1:
        print("String passed to inverse unicode numeral representation %s:" % string)
    unicode_of_string_inverse = []
    for character in string:
        number_of_char = chr(int(character))
        unicode_of_string_inverse.append(number_of_char)
    if debug == 1:
        print(
            "DEBUG: Inverse unicode numeral representation of all the string characters is: %s"
            % unicode_of_string_inverse
        )
    joining_unicode_of_string_inverse = [str(int) for int in unicode_of_string_inverse]
    return "".join(joining_unicode_of_string_inverse)


def encoder(message, N, e, debug):
    unicode_of_encoded_string = []
    length_N = len(str(N))

    unicode_of_string_split = [
        message[i : i + (length_N - 1)] for i in range(0, len(message), (length_N - 1))
    ]
    if debug == 1:
        print(
            "DEBUG: The string after being split to chunks of elements sized %d produces the following list: %s"
            % ((length_N - 1), unicode_of_string_split)
        )
        print(
            "DEBUG: Length (number of elements) of the split list: %d"
            % len(unicode_of_string_split)
        )

        print("Revealing unencrypted message:")
        print("".join(unicode_of_string_split))

    print(
        "Encoding your input, this may take a while depending on the size of the primes and the slicer value."
    )

    for element in unicode_of_string_split:
        element = int(element)
        encoded_element = (element ** e) % N
        if debug == 1:
            print("%d encoded as %d" % (element, encoded_element))
        unicode_of_encoded_string.append(encoded_element)

    return unicode_of_encoded_string


# decoder() arguments: N, e, decoder_key (only if you have it), encoded_message, list_of_primes (optional, pass an empty list_of_primes if not passing decoder_key as "generate_decryption_key")
def decoder(N, e, decoder_key, encoded_message, list_of_primes, debug):
    please_wait = print("Decrypting based upon your input, this may take a while.")
    if decoder_key == "generate_decryption_key":
        print("Preparing your decryption key...")
        (
            s,
            decoder_key,
            hcf,
        ) = euclidean_algorithm_for_two_or_more_numbers_modular.bezouts_identity(
            (list_of_primes[0] - 1) * (list_of_primes[1] - 1), e
        )
        if decoder_key < 0:
            decoder_key = euclidean_algorithm_for_two_or_more_numbers_modular.bezouts_identity_positive(
                decoder_key, (list_of_primes[0] - 1) * (list_of_primes[1] - 1), e
            )
            if debug == 1:
                print(
                    "The smallest decryption key was negative -- therefore, additional computation was performed to find a positive decryption key."
                )

        print("Writing decryption key...")
        return decoder_key
    elif decoder_key != "":
        please_wait
        naive_count = 0
        decoded_list = []
        encoded_message = encoded_message.split(",")  # Necessary to remove the commas
        while naive_count < len(encoded_message):
            decoded_piece = (int(encoded_message[naive_count]) ** decoder_key) % N
            if debug == 1:
                # print("Decoder key: %d\nN value: %d" % (decoder_key, N))
                print(
                    "%d decoded as: %d"
                    % (int(encoded_message[naive_count]), decoded_piece)
                )
            decoded_list.append(decoded_piece)
            naive_count += 1
        return decoded_list
    else:
        please_wait
        print(
            "Feature not yet implemented, this software can not decrypt without decryption keys in this current version of the program."
        )
        # To do: implement decoding without knowing the decoder key, steps shown below.
        # Find (p-1)(q-1), might be able to using N and e.
        # p_plus_q = -1*((p - 1)*(q - 1) - N - 1) # Solve for p + q
        # Solve the equation for p and q of: x^2 - (p + q)x + N = 0 # Second step
        # Find p and q, find positive integer s such that se congruent to 1 mod (p-1)(q-1) of the euclidean algorithm (p-1)(q-1)
        # Decode each encrypted digits mod decoder key
        # Return decoded list
        pass


def write_to_file(
    pubkey,
    privkey,
    unencrypted_message,
    encoded_message,
    N,
    e,
    list_of_primes,
    unicode_numeral_message,
    debug,
    unicode_of_string,
    is_file,
    file_name,
    encode_or_decode,
    decoder_key,
):

    f = open("keys.txt", "w")

    # Instructions
    f.write(
        "Note: Public keys are of the form (N, e) and private keys are of the form (Prime_1, Prime_2).\n"
    )
    f.write(
        "To Encode using any of those sets of public keys, perform the following steps: \n1. Convert your data into a string of numbers by some process and remember the inverse of this process in order to deconvert later.\n2. Break up the string into a sequence of numbers with fewer digits than N.\n3. Calculate for each broken part its congruence to the power of e mod N.\n4. Enjoy your encrypted data, only those with the private keys can decode it.\n"
    )
    f.write(
        "To Decode using any of those sets of public keys, the steps you'll have to take depend on how much you know about the encoded data. \n(If you already have the decoder key): Raise each of the listed numbers of the encoded data to the power of the decoder key then work out its congruence modulo N.\nIf you do not have the decoder key, then find out what (p-1)(q-1) is by using the public keys of equation (p-1)(q-1) = N - p - q + 1, then solve the following equation for p + q: (p-1)(q-1) = x^2 - (p+q)x + N = 0. Afterwards, work out hcf((p-1)(q-1),e) where e and (p-1)(q-1) are coprime, finally work backwards to find an integer d such that d*e is congruent to 1 mod N, with d positive, this is your decoder key. Follow the steps from having the decoder_key if you get this far.\n"
    )

    # Keys and message
    if encode_or_decode == "e":
        f.write(
            "Public keys: %s\nPrivate keys: %s\nDecryption key: %s\n"
            % (
                pubkey,
                privkey,
                decoder_key,
            )
        )
    elif encode_or_decode == "d":
        f.write(
            "Public keys: %s\nDecryption key: %s\n"
            % (
                pubkey,
                decoder_key,
            )
        )

    if is_file != "1":
        f.write(
            "Encoded message associated with the above keys: %s\nUncrypted message associated with the above keys: %s \n"
            % (str(encoded_message)[1:-1], unencrypted_message)
        )
        # To do: figure out how to find the proper unicode numeral representation for the decrypted data set when decrypting (not encrypting), might not be possible though, the main issue is that the decrypted files are hard to guess what their unicode representation would be for each letter.
        if encode_or_decode == "e":
            if unicode_numeral_message == 1:
                inverse_unicode_string = inverse_unicode_numeral(
                    unicode_of_string, debug
                )
                f.write(
                    "Decrypted message in character unicode form: %s"
                    % inverse_unicode_string
                )
    else:
        if encode_or_decode == "e":
            file_name_appended = "".join(("encrypted_", file_name))
        elif encode_or_decode == "d":
            file_name_appended = "".join(("decrypted_", file_name))
        file_acquired = open(file_name_appended, "w")
        file_acquired.write(str(encoded_message)[1:-1])
        file_acquired.close()

    # Close files
    f.close()

    # Print to terminal
    print(
        "The public key is: (%d, %d), share this with people you want to be able to encode."
        % (N, e)
    )
    if encode_or_decode == "e":
        print(
            "The private key is: (%d, %d), keep this a secret."
            % (list_of_primes[0], list_of_primes[1])
        )

    if is_file != "1":
        print(
            "The keys, encrypted message, decrypted message and instructions on how to encode/decode the messages has been written into keys.txt in this file's directory."
        )
    else:
        if encode_or_decode == "e":
            print(
                "The keys and instructions on how to encode/decode the file have been written into keys.txt in your local directory.\nEncrypted file with name %s has been created in your local directory."
                % file_name_appended
            )
        elif encode_or_decode == "d":
            print(
                "The keys and instructions on how to encode/decode the file have been written into keys.txt in your local directory.\nDecrypted file with name %s has been created in your local directory."
                % file_name_appended
            )
