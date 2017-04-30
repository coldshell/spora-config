# README
---

This script decrypt the embedded "configuration" of Spora automatically.


## Requirements

Installation of python requirements:

```
pip install -r requirements.txt
```

Installation of [LIEF](https://lief.quarkslab.com/)(binary manipulation), see their
[doc](https://lief.quarkslab.com/doc/installation.html#python).


Installation of [Grap](https://bitbucket.org/cybertools/grap)(graph matching), see the README.

## Usage

The tool can be launched by using the following command:
```
$ ./spora-config.py [options] unpacked_spora.bin
```

###### Examples

Simple verbose mode:

```
$ ./spora_config.py -v  samples/154e4db0dcc4bde7d59056c0e6fa6392

-=[~~~~~~~~~~~~~~~~~~~Spora Config~~~~~~~~~~~~~~~~~~~]=-

AES KEY: 0x545a7a3c2c74072a33e2092d0223270810c39ac445546b6ae4fe059521a8cd2f
Found decryption function at 0x405b4d
4 calls to decrypt function found.

File decrypted SHA256: 3028910b74dfafe5ef3d69d17f3094c85534692703cd3b5713135713241ec1be, size: 288

File decrypted SHA256: 55646d269cc8a3d223ae86cb3b886ca08773f259ceb9b3082d582785df0034f1, size: 12288

File decrypted SHA256: 377b43515810ce8b95513f4bce7743de1f83fe5d367b398218d1b377765f3f59, size: 32

File decrypted SHA256: 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925, size: 32

```

Increase the verbosity:

```
$ ./spora_config.py -vv  samples/2b2bfdbd61aefe1f960b592f3557b415

-=[~~~~~~~~~~~~~~~~~~~Spora Config~~~~~~~~~~~~~~~~~~~]=-

AES KEY: 0xf6b751d5cb4bfa4a0e7d56aa14f3e64068bdf5347a658ed446c40ac7794c82f6
Looking for entrypoint with pattern:

    digraph decrypt_func_begin{
        ep [label="ep", cond="nfathers >= 4 and address >= 0x4061d0 and address <= 0x4061ee", getid="ep"]
    }

Found decryption function at 0x4061df
Looking for calls to decrypt function with pattern:

    digraph push_call_decrypt{
        push [label="push", cond="opcode is push", repeat=2, getid=push]
        junk [label="junk", cond=true, minrepeat=0, maxrepeat=1, lazyrepeat=true]
        call [label="call", cond="opcode is call"]
        entrypoint [label="entrypoint", cond="address == 0x4061df"]

        push -> junk
        junk -> call
        call -> entrypoint [childnumber=2]
    }

4 calls to decrypt function found.

File decrypted SHA256: 0a9699376325755435d196e49a8c42105174df46b67857c527f5738606e4991c, size: 288
Entropy of 0a9699376325755435d196e49a8c42105174df46b67857c527f5738606e4991c: before = 0.904898456726, after = 0.717588566079

File decrypted SHA256: 6c0e84bd24f61e9903f80efd8b0e54c3dac352e6f16b0e41bcc0db391f31bc3b, size: 12352
Entropy of 6c0e84bd24f61e9903f80efd8b0e54c3dac352e6f16b0e41bcc0db391f31bc3b: before = 0.997832075339, after = 0.7412672809

File decrypted SHA256: 377b43515810ce8b95513f4bce7743de1f83fe5d367b398218d1b377765f3f59, size: 32
Entropy of 377b43515810ce8b95513f4bce7743de1f83fe5d367b398218d1b377765f3f59: before = 0.59861372041, after = 0.223193816036

File decrypted SHA256: 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925, size: 32
Entropy of 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925: before = 0.609375, after = 0.0

```

You can print the decrypted configuration:

```
$ ./spora_config.py -vp samples/2b2bfdbd61aefe1f960b592f3557b415

-=[~~~~~~~~~~~~~~~~~~~Spora Config~~~~~~~~~~~~~~~~~~~]=-

AES KEY: 0xf6b751d5cb4bfa4a0e7d56aa14f3e64068bdf5347a658ed446c40ac7794c82f6
Found decryption function at 0x4061df
4 calls to decrypt function found.

File decrypted SHA256: 0a9699376325755435d196e49a8c42105174df46b67857c527f5738606e4991c, size: 288
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8TiuLl9ElZxgRrJOtrFth3oSO
kn33/da8WB06mZLDxZ61oDA+NbE6Ie7CgHxNu2nsa+E09H1EKcfXY4NhjPpc0zDP
PrwEgHZ+JA0SruQhFs/xII/F4z9/J3RAIMGmoj/IlWijQwanrbMyVe/aNVtnaApa
OTYYjoVjCpZR5D7O5wIDAQAB
-----END PUBLIC KEY-----
...
...
```

You can save this in a directory:

```
$ ./spora_config.py samples/d9dce533a91a1de4df02aa4f02fccaff -v -o output

-=[~~~~~~~~~~~~~~~~~~~Spora Config~~~~~~~~~~~~~~~~~~~]=-

AES KEY: 0xc4e538bdecbb5181dc0c6eda6faf2cd0f2bde2dcac8a24309032700c5119523c
Found decryption function at 0x405b6d
4 calls to decrypt function found.

File decrypted SHA256: 3028910b74dfafe5ef3d69d17f3094c85534692703cd3b5713135713241ec1be, size: 288

File decrypted SHA256: 23d323a17d6132a3d4aba143dd71fe0a00b06cd5edf10147bd8c0f187a80ace2, size: 12320

File decrypted SHA256: 377b43515810ce8b95513f4bce7743de1f83fe5d367b398218d1b377765f3f59, size: 32

File decrypted SHA256: 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925, size: 32

$ tree output
output
└── d9dce533a91a1de4df02aa4f02fccaff
    ├── 23d323a17d6132a3d4aba143dd71fe0a00b06cd5edf10147bd8c0f187a80ace2
    ├── 3028910b74dfafe5ef3d69d17f3094c85534692703cd3b5713135713241ec1be
    ├── 377b43515810ce8b95513f4bce7743de1f83fe5d367b398218d1b377765f3f59
    ├── 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
    └── AES256.key

```
