import random

list_of_found_primes = []


def DisplayError(ErrorNumber, n):
    if ErrorNumber == 0:
        print("Please follow the directions in the program")
    elif ErrorNumber == 1:
        print(
            "Illogical input: the number of coprime integers that you've plugged in is more than the possible coprime integers that are smaller than the prime number we are checking for primality."
        )
    elif ErrorNumber == 2:
        print("Input is not an integer, will not perform computation.")
    elif ErrorNumber == 3:
        print("%d is not prime, as it is divisible by 2." % n)
    elif ErrorNumber == 4:
        print("%d is not prime, as the integer 1 is by definition not prime." % n)


def primality_tester(details, prime_to_check, coprimes_to_test_against):
    n, k = 0, 0
    try:
        n = int(prime_to_check)
        k = int(coprimes_to_test_against)
    except ValueError:
        DisplayError(2, n)
    if n % 2 == 0:
        if not details == "-1":
            DisplayError(3, n)
        else:
            return "is not prime"
    elif n == 1:
        if not details == "-1":
            DisplayError(4, n)
        else:
            return "is not prime"
    elif n - 1 > k > 0:
        # Find all factors of 2 of (n-1), we do this now instead of later for optimization purposes.
        x = 1
        factors_of_2 = 0
        while (n - 1) % (2 * x) == 0:
            factors_of_2 += 1
            x = x * 2
        # Choose k integers coprime to n and smaller than n but still positive.
        KIntegersChosenAtRandom = random.sample(
            range(2, n), k
        )  # Randomly inserts k random numbers between n-1 and 2 (inclusive of endpoints) into a list with no repeats.
        chosen_at_random = 0
        g = 0
        bases_passed = 0
        while chosen_at_random < k and g != "not prime":
            chosen_at_random += 1
            b = KIntegersChosenAtRandom.pop(
                0
            )  # Pop command returns value of index it deletes, so in this case we are assigning the value we removed to b
            t = 1
            count_congruence_to_1 = 0
            iterated_over_factors_of_2 = 0
            while iterated_over_factors_of_2 <= factors_of_2:
                iterated_over_factors_of_2 += 1
                if ((b ** ((n - 1) // (t))) % n) == (n - 1):
                    if details == "2":
                        print(
                            "%d passes miller's test with base %d, because %d^%d mod %d gives remainder %d"
                            % (
                                n,
                                b,
                                b,
                                (n - 1) // (t),
                                n,
                                ((b ** ((n - 1) // (t))) % n),
                            )
                        )
                    elif details == "1":
                        bases_passed += 1
                        print(
                            "%d passed miller's test with %d coprime integers out of %d."
                            % (n, bases_passed, k)
                        )
                    iterated_over_factors_of_2 = factors_of_2 + 1  # Forces a stop
                elif ((b ** ((n - 1) // (t))) % n) == 1:
                    count_congruence_to_1 += 1
                    if count_congruence_to_1 == (factors_of_2 + 1):
                        if details == "2":
                            print(
                                "%d passes miller's test with base %d, because %d to the power of f, where f is of the form %d/(2 to the power of i) and i can be any number between 0 and the count of how many copies of the factors of 2 that %d contains in its product, inclusive of the endpoints."
                                % (n, b, b, (n - 1), (n - 1))
                            )
                        elif details == "1":
                            bases_passed += 1
                            print(
                                "%d passed miller's test with %d coprime integers out of %d."
                                % (n, bases_passed, k)
                            )
                else:
                    if not details == "-1":
                        print(
                            "%d is not prime with absolute certainty, since %d^%d mod %d is congruent to %d."
                            % (n, b, (n - 1) // (t), n, ((b ** ((n - 1) // (t))) % n))
                        )
                    g = "not prime"
                    iterated_over_factors_of_2 = factors_of_2 + 1  # Forces a stop
                t = t * 2
        if not g == "not prime":
            if not details == "-1":
                print(
                    n,
                    "is prime with more than {:.10%}".format(1 - (1 / 4) ** k),
                    "chance of a correct deduction.",
                )
                if not n in list_of_found_primes:
                    list_of_found_primes.append(n)
            else:
                return "is prime"
        elif g == "not prime" and details == "-1":
            return "is not prime"
    else:
        DisplayError(1, n)