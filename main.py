from arl_dilithium import generate_keypair_random as generate_keypair_random_arl
from tdc_falcon import generate_keypair_random as generate_keypair_random_tdc
import multiprocessing
import hashlib
import time

code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }


def sha256(v):
    return hashlib.sha256(v)


def doublehash256(v):
    return sha256(sha256(v).digest())


def hash160(v):
    return ripemd(hashlib.sha256(v).digest())


def ripemd(v):
    r = hashlib.new('ripemd160')
    r.update(v)
    return r


def checksum(v):
    checksum_size = 4
    return doublehash256(v).digest()[:checksum_size]


def decode(string, base):
    if base == 256 and isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            return d
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result


def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")


def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element * pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result


def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg


def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)


def from_string_to_bytes(a):
    return a if isinstance(a, bytes) else bytes(a, 'utf-8')


def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()


def from_int_to_byte(a):
    return bytes([a])


def bin_to_b58check(inp, magicbyte=0):
    if magicbyte == 0:
        inp = from_int_to_byte(0) + inp
    while magicbyte > 0:
        inp = from_int_to_byte(magicbyte % 256) + inp
        magicbyte //= 256

    leadingzbytes = 0
    for x in inp:
        if x != 0:
            break
        leadingzbytes += 1

    checksum = bin_dbl_sha256(inp)[:4]
    return '1' * leadingzbytes + changebase(inp + checksum, 256, 58)


BITCOIN_ALPHABET = \
    b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

BITCOIN_ALPHABET_STR = \
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


number_addresses = 0


def scrub_input(v):
    if isinstance(v, str):
        v = v.encode('ascii')
    return v


def b58encode_int(i, default_one= True, alphabet = BITCOIN_ALPHABET):
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    base = len(alphabet)
    while i:
        i, idx = divmod(i, base)
        string = alphabet[idx:idx+1] + string
    return string


def b58encode(
    v, alphabet= BITCOIN_ALPHABET
):
    """
    Encode a string using Base58
    """
    v = scrub_input(v)
    v = v.lstrip(b'\0')
    acc = int.from_bytes(v, byteorder='big')  # first byte is most significant
    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return result


def _generate_publicaddress3(pubkey, prefix):
    prefix_redeem = b'\x00\x14'
    redeem_script = hash160(prefix_redeem + hash160(pubkey).digest()).digest()  # 20 bytes
    m = prefix + redeem_script
    c = checksum(m)
    return b58encode(m + c)


little_bytes_07 = 0x07.to_bytes(1, "little")
little_bytes_01 = 0x01.to_bytes(1, "little")
little_bytes_arl = 0x17.to_bytes(1, "little")
little_bytes_tdc = 0x41.to_bytes(1, "little")


def gen_user_date_string(seconds):
    days = int(seconds)//(3600*24)
    return time.strftime(f"{days} days %H hours %M months %S seconds", time.gmtime(int(seconds)))


def get_search_speed(count, threads_count, start_time, count_addresses):
    speed = int(count * threads_count / (time.time() - start_time))
    print(
        f"Search speed: {speed} addresses per second\n"
        f"It will take approximately "
        f"{gen_user_date_string(count_addresses / speed)} "
        f"to find your address")


def gen_address(generator, contains,
                started, file,
                little_bytes,
                threads_count,
                number_threads,
                number_addresses):
    started_len = len(started)
    started = bytes(started, "UTF-8")
    contains = bytes(contains, "UTF-8")
    start_time = time.time()
    sumlen = 0

    if started_len != 0:
        sumlen += started_len - 1
    sumlen += len(contains)

    count = 0
    if number_threads == 0:
        count_addresses = 1
        for i in range(sumlen):
            count_addresses *= 58
        if contains and started:
            while True:
                public_key, secret_key = generator()
                count += 1
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if contains in address and started == address[:started_len]:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Started at {started} and Contains {contains}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))
                if count == number_addresses:
                    get_search_speed(count, threads_count, start_time, count_addresses)
                    count = 0
                    start_time = time.time()
        elif contains:
            while True:
                public_key, secret_key = generator()
                count += 1
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if contains in address:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Contains {contains}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))
                if count == number_addresses:
                    get_search_speed(count, threads_count, start_time, count_addresses)
                    count = 0
                    start_time = time.time()
        elif started:
            while True:
                public_key, secret_key = generator()
                count += 1
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if started == address[:started_len]:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Started at {started}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))
                if count == number_addresses:
                    get_search_speed(count, threads_count, start_time, count_addresses)
                    count = 0
                    start_time = time.time()
    else:
        if contains and started:
            while True:
                public_key, secret_key = generator()
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if contains in address and started == address[:started_len]:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Started at {started} and Contains {contains}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))
        elif contains:
            while True:
                public_key, secret_key = generator()
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if contains in address:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Contains {contains}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))
        elif started:
            while True:
                public_key, secret_key = generator()
                address = _generate_publicaddress3(little_bytes_07 + public_key, little_bytes)
                if started == address[:started_len]:
                    if file:
                        with open(f"{file}", "a") as f:
                            f.write(f"{address}:{bin_to_b58check(secret_key + little_bytes_01 + public_key, 125)}\n")
                    else:
                        print(f"Started at {started}", address,
                              bin_to_b58check(secret_key + little_bytes_01 + public_key, 125))


if __name__ == '__main__':
    import argparse
    import sys

    message = "Address Miner is a address mining client. " \
              "If you like this piece of software, please "  \
              "consider supporting its future development via " \
              "donating to one of the addresses indicated in the " \
              "README.md file\n\n" \
              "PARAMS:\n" \
              "-a address type, TDC or ARL\n" \
              "-s what should the address start with\n" \
              "-c what should be in the address\n" \
              "-t the number of threads involved in the search (your number cores by default)\n" \
              "-f output file(writes to console by default)\n"

    print(message)

    cpu_count = multiprocessing.cpu_count()
    parser = argparse.ArgumentParser(description=message)

    parser.add_argument('-s', '-started', dest='started', default="",
                        help='Start address')
    parser.add_argument('-с', '-contains', dest='contains', default="",
                        help='Сontains')
    parser.add_argument('-t', '--threads', dest='threads', default=cpu_count, help='Сount threads',
                        metavar="THREADS")
    parser.add_argument('-f', '--file', dest='file', default="", help='Output file')
    parser.add_argument('-a', '--address', dest='address', default="ARL", help='address type, TDC or ARL')



    procs = []
    options = parser.parse_args(sys.argv[1:])

    if options.address.lower() == "tdc" or options.address.lower() == "tidecoin":
        generator = generate_keypair_random_tdc
        little_bytes = little_bytes_tdc
        if options.started:
            if options.started[0] != "T":
                options.started = "T" + options.started
        number_addresses = 5000
    else:
        generator = generate_keypair_random_arl
        little_bytes = little_bytes_arl
        if options.started:
            if options.started[0] != "A":
                options.started = "A" + options.started

        number_addresses = 50000

    if options.started:
        options.started = options.started[0] + options.started[1].upper() + options.started[2:]

        for char in options.started:
            if char not in BITCOIN_ALPHABET_STR:
                print(f"Invalid character {char}, list of allowed characters:\n"
                      f"{BITCOIN_ALPHABET_STR}")
                raise Exception

    for char in options.contains:
        if char not in BITCOIN_ALPHABET_STR:
            print(f"Invalid character {char}, list of allowed characters:\n"
                  f"{BITCOIN_ALPHABET_STR}")
            raise Exception

    if not options.contains and not options.started:
        print("Error! Сontains or started must be filled")
        raise Exception

    for number in range(int(options.threads)):
        proc = multiprocessing.Process(target=gen_address, args=(generator, options.contains,
                                                                 options.started, options.file,
                                                                 little_bytes,
                                                                 int(options.threads),
                                                                 number,
                                                                 number_addresses))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()