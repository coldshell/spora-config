#!/usr/bin/env python2

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from entropy import shannon_entropy
from grap_disassembler import disassembler
from pygrap import *
import argparse
import lief


def usage():
    parser = argparse.ArgumentParser(description="Decrypt spora's config")
    parser.add_argument('file', action='store', help="Spora sample")
    parser.add_argument("-v", "--verbose", help="Increase verbosity -v, -vv", action="count")
    parser.add_argument("-p", "--print-config", help="Print the decrypted configuration",
                        action="store_true")
    parser.add_argument("-o", '--output-dir', action='store',
                        help="Output directory to save Spora's config")

    return parser.parse_args()


def get_bin_bytes(bin, va, size):
    rva = va - bin.optional_header.imagebase
    return bin.get_content_from_virtual_address(rva, size)


def find_func_addr(args, start_addr, test_graph):
    """This function finds the entrypoint with a dirty hack."""

    addr_cond = "address >= {:#x} and address <= {:#x}".format(start_addr - 30, start_addr)
    entrypoint_pattern = """
    digraph decrypt_func_begin{
        ep [label="ep", cond="nfathers >= 4 and FILL_ADDR_COND", getid="ep"]
    }
    """.replace("FILL_ADDR_COND", addr_cond)

    if args.verbose >= 2:
        print "Looking for entrypoint with pattern: "
        print "{:}".format(entrypoint_pattern)

    matches_ep = match_graph(entrypoint_pattern, test_graph)

    if len(matches_ep) != 1 or len(matches_ep["decrypt_func_begin"]) != 1:
        print "Error: Entrypoint not found, exiting"
        sys.exit(1)

    ep = hex(int(matches_ep["decrypt_func_begin"][0]["ep"][0].info.address))

    if args.verbose:
        print "Found decryption function at {:}".format(ep)

    return ep


def get_calls(args, ep, test_graph):
    """ Get Xrefs"""
    push_call_pattern = """
    digraph push_call_decrypt{
        push [label="push", cond="opcode is push", repeat=2, getid=push]
        junk [label="junk", cond=true, minrepeat=0, maxrepeat=1, lazyrepeat=true]
        call [label="call", cond="opcode is call"]
        entrypoint [label="entrypoint", cond="address == FILL_ADDR"]

        push -> junk
        junk -> call
        call -> entrypoint [childnumber=2]
    }
    """.replace("FILL_ADDR", ep)

    if args.verbose >= 2:
        print "Looking for calls to decrypt function with pattern:"
        print "{:}".format(push_call_pattern)

    matches_calls = match_graph(push_call_pattern, test_graph)

    if len(matches_calls) == 0:
        print "error: No call found, exiting"
        sys.exit(1)

    if args.verbose:
        print len(matches_calls["push_call_decrypt"]), "calls to decrypt function found."

    len_str = []
    for m in matches_calls["push_call_decrypt"]:
        # Work on matches with immediate arguments such as:
        # PUSH (between 2 and 5) with hex arguments (for instance: 9, 0x12 or 0x4012a3)
        # CALL entrypoint
        if len(m["push"][-2].info.arg1) == 1 or "0x" in m["push"][-2].info.arg1:

            len_str.append({"len": int(m["push"][-2].info.arg1, 16),
                            "str": int(m["push"][-1].info.arg1, 16)})

    return len_str


def decrypt_str(args, binary, len_str, key):
    """Decrypt Spora's config"""

    # Save AES key
    if args.output_dir:
        out_dir = "{:}/{:}/".format(args.output_dir, os.path.basename(args.file))
        out_path = out_dir + "AES256.key"

        # Check for the output directory
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # Write the decrypted file
        with open(out_path, 'w') as f:
            f.write(key)

    # Decrypt data
    for call in len_str:
        # Init Crypto stuff
        h = SHA256.new()
        c = AES.new(key, AES.MODE_CBC, '\x00' * 16)

        enc_bytes_list = get_bin_bytes(binary, call["str"], call["len"])
        enc_bytes_str = b''.join([chr(i) for i in enc_bytes_list])

        dec_bytes_str = c.decrypt(enc_bytes_str)

        h.update(dec_bytes_str)
        entropy = {"enc": shannon_entropy(enc_bytes_str),
                   "dec": shannon_entropy(dec_bytes_str)}

        # Print file hash and size
        if args.verbose >= 1:
            print "\nFile decrypted SHA256: {:}, size: {:}".format(h.hexdigest(), call["len"])

        # Print entropy
        if args.verbose >= 2:
            print "Entropy of {:}: before = {:}, after = {:}".format(h.hexdigest(),
                                                                     entropy["enc"],
                                                                     entropy["dec"])
        # Save the decrypted file
        if args.output_dir:
            out_path = out_dir + h.hexdigest()

            # Write the decrypted file
            with open(out_path, 'w') as f:
                f.write(dec_bytes_str)

        if args.print_config:
            print "{:}".format(dec_bytes_str)


def main():
    # usage
    args = usage()

    # Init
    aeskey_offset = 12
    SPORADOT = "spora-crypto.dot"
    bin_path = args.file
    dot_path = args.file + ".dot"
    binary = lief.parse(bin_path)

    if not os.path.isfile(dot_path):
        disassembler.disassemble_file(bin_path=bin_path, dot_path=dot_path)

    # Load graphs
    test_graph = getGraphFromPath(dot_path)

    # Search for matches
    matches_crypto = match_graph(SPORADOT, test_graph)

    # Get AES key
    try:
        aes_push = matches_crypto["spora_crypto"][0]["AESKey"][0]
    except:
        print "Key not found"
        sys.exit(1)

    ptr_publickeystruc = int(aes_push.info.arg1, 16)
    aes_key_list = get_bin_bytes(binary, (ptr_publickeystruc + aeskey_offset), 32)
    aes_key_str = b''.join([chr(i) for i in aes_key_list])

    if args.verbose:
        print "\n-=[{:~^50}]=-\n".format("Spora Config")
        print "AES KEY: 0x%s" % aes_key_str.encode("hex")

    # Get the EP of the function
    ep = find_func_addr(args, aes_push.info.address, test_graph)

    # Get calls to the decrypt function
    len_str = get_calls(args, ep, test_graph)

    # Decrypt Spora's config
    decrypt_str(args, binary, len_str, aes_key_str)


if __name__ == "__main__":
    main()
