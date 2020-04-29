# Simple fuzzers for libssh

This directory contains fuzzer programs, that are usable either in
oss-fuzz infrastructure or suitable for running fuzzing locally or
even for reproducing crashes with given trace files.

When building with clang, fuzzers are automatically built with address
sanitizer. With gcc, they are built as they are without instrumentation,
but they are suitable for debugging.

## Background

Fuzzing ssh protocol is complicated by the way that all the communication
between client and server is encrypted and authenticated using keys based
on random data, making it impossible to fuzz the actual underlying protocol
as every change in the encrypted data causes integrity errors. For that reason,
libssh needs to implement "none" cipher and MAC as described in RFC 4253
and these need to be used during fuzzing to be able to accomplish
reproducibility and for fuzzers to be able to progress behind key exchange.

## Corpus creation

For effective fuzzing, we need to provide corpus of initial (valid) inputs that
can be used for deriving other inputs. libssh already supports creation of pcap
files (packet capture), which include all the information we need for fuzzing.
This file is also created from date before encryption and after decryption so
it is in plain text as we expect it, but we still need to adjust configuration
to use none cipher for the key exchange to be plausible.

### Creating packet capture using example libssh client

 * Compile libssh with support for none cipher and pcap:

    cmake -DWITH_INSECURE_NONE=ON -DWITH_PCAP=ON ../

 * Create a configuration file enabling none cipher and mac:

    printf 'Ciphers none\nMACs none' > /tmp/ssh_config

 * Generate test host key:

    ./examples/keygen2 -f /tmp/hostkey -t rsa

 * Run example libssh server:

    ./examples/samplesshd-cb -f /tmp/ssh_config -k /tmp/hostkey -p 22222 127.0.0.1

 * In other terminal, run the example libssh client with pcap enabled (use mypassword for password):

    ./examples/ssh-client -F /tmp/ssh_config -l myuser -P /tmp/ssh.pcap -p 22222 127.0.0.1

 * Kill the server (in the first terminal, press Ctrl+C)

 * Convert the pcap file to raw traces (separate client and server messages) usable by fuzzer:

    tshark -r /tmp/ssh.pcap -T fields -e data -Y "tcp.dstport==22222" | tr -d '\n',':' | xxd -r -ps > /tmp/ssh_server
    tshark -r /tmp/ssh.pcap -T fields -e data -Y "tcp.dstport!=22222" | tr -d '\n',':' | xxd -r -ps > /tmp/ssh_client

 * Now we should be able to "replay" the sessions in respective fuzzers, getting some more coverage:

    LIBSSH_VERBOSITY=9 ./tests/fuzz/ssh_client_fuzzer /tmp/ssh_client
    LIBSSH_VERBOSITY=9 ./tests/fuzz/ssh_server_fuzzer /tmp/ssh_server

   (note, that the client fuzzer fails now because of invalid hostkey signature; TODO)

 * Store the appropriately named traces in the fuzers directory:

    cp /tmp/ssh_client tests/fuzz/ssh_client_fuzzer_corpus/$(sha1sum /tmp/ssh_client | cut -d ' ' -f 1)
    cp /tmp/ssh_server tests/fuzz/ssh_server_fuzzer_corpus/$(sha1sum /tmp/ssh_server | cut -d ' ' -f 1)
