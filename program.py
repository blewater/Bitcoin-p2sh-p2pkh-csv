"""
Summary: Find Utxos paid to a P2SH address and transfer their btc to the lucky P2PKH_Addr_To addresss.
Supports both blocks and relative seconds(*) wait configuration values being 0
for confirming immediate successful submission.
--or setting the relative blocks and relative seconds(*) waiting value.
(*)Though testing the seconds wait function seemed impractical as to wait for value greater
than 128 * 512 blocks of time.
(**) Using a public key in program 1 has not been tested. There's related comment.

-- Uses the bitcoin-utils lib. -- Great library with a couple of glitches. See below ;)
Also tested with python-bitcoinlib but found issues with its DER encoding during submissions.

*** Precondition: bitcoin-cli needs to in the path otherwise,
this humble deliverable can't find utxo or submit transactions. ***

Configuration is provided in program.conf. See related content for details.

Both program 1 and 2 run from the same file: python program.py
If the configuration value RunProgram == 1, then only the redeem script gets created.
For RunProgram value == 2, both program 1 and 2's functionality run.

You may run it in the same path with program.conf

    python program.py

This assignment has been tested with bitcoin node 13.1 in ubuntu, 13.2 windows.

Yes it works for single and multiple input UTXO transactions with the following exceptions:

1. Does not support block wait value of 1...128 I think. For those submissions the bitcoin node
responds with "mandatory-script-verify-flag-failed (Non-canonical DER signature)" after
the wait period is over. However, tested ok, and submits transactions successfully with 130 and above.
Did not test values of 129, 128 and many intermediate in the range of 1-128.
I did not realize this out initially that it might be related to the signed integer issue
of the library. I'd love your feedback if it's related to my code.
I always pad zeroes to 4 or 8 total length.

2. Some input UTXO transaction ids raise library exception and crash
during the signing of the input transactions.
After investigating it, I could't find anything related to my code. Not using those offending
UTXO transaction ids makes the failure go away :)

Here's the library exception:
  File "/Python3/lib/site-packages/bitcoinutils\keys.py", line 314, in sign_input
    new_S = unhexlify( format(new_S_as_bigint, 'x') )
binascii.Error: Odd-length string

That also took time before I gave up and would love
feedback if it's mine issue.

------------------------------------------------------------------------------------
Example Submission 1:

Running Program *** 2 ***

seconds to wait: 0, blocks to wait: 0
sequence number in little endian format: 00000000

redeem hex: 2103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac
Redeem script generated P2SH addr: 2NFbu9tEGnLKZYQtxNgiA7DSeN61hDe9SkA

For the P2SH address: 2NFbu9tEGnLKZYQtxNgiA7DSeN61hDe9SkA found these UTXOs:

Trx id: d2c9a1fe7164b7525670ad76588092454751e29f8234e76a67875f96331bc0a4, vout: 0 amount: 1.1


Size in KB: 0.298828125, estimated btc fees: 2.9882812500000002e-06, total amount to be transferred: 1.1


Signed raw transaction:
0200000001a4c01b33965f87676ae734829fe251474592805876ad705652b76471fea1c9d2000000008447304402205f1bf7918f70b0c82bf495309a3c104d8d3a3edc7789b79537b8419eb322dcc6022017ea79a4007502d4de305112b91293a4b2e336fb00535509b39038112d141406013b2103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac000000000155768e06000000001976a914266ae37985ef74e1d6089897639578c0c990bd0a88ac00000000

Submitting raw transaction to local node...

Success or previously submitted; trx id: 4a48c21046b8e068ccfc992b14031f9cdc536ea1a3bd82a1cf411b85774943bc

------------------------------------------------------------------------------------
Example submission 2:
λ python program.py

Running Program *** 2 ***

seconds to wait: 0, blocks to wait: 129
sequence number in little endian format: 81000000

redeem hex: 028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac
Redeem script generated P2SH addr: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp

For the P2SH address: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp found these UTXOs:

Trx id: 7d3718fd53e887e580dffe659e6e562e32aa5abed86625def8f8b0835d2760da, vout: 1 amount: 1.1
Trx id: 31649c117b8c5daca6f497a0cf45f45676ff3c3a39442c62f5f41a283430a547, vout: 0 amount: 1.1
Trx id: 94f30f847775e3ddef43f617e08819cd9b7c8751f6eab1451b345562afe92d64, vout: 0 amount: 1.1


Size in KB: 0.587109375, estimated btc fees: 5.871093750000001e-06, total amount to be transferred: 3.3000000000000003


Signed raw transaction:
0200000003da60275d83b0f8f8de2566d8be5aaa322e566e9e65fedf80e587e853fd18377d01000000894730440220702dd7585f66abebb87d81e187006d9ee62300b79cc82d6633796cae2482d6ea02201cf6e900cd4f3d7c8239a3989336eef0e65f8ad6abd80d14092fb2957a3904d50140028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac8100000047a53034281af4f5622c44393a3cff7656f445cfa097f4a6ac5d8c7b119c6431000000008a483045022100800f4aa1cc48e08ff2ce3918f79e545db1336f65ffa5d2aebc8fcc7ab60c6f7d022047a7b2553ebfeea53dadd0f2a85fbeefda5ab1c918541805be3731475631811f0140028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac81000000642de9af6255341b45b1eaf651877c9bcd1988e017f643efdde37577840ff39400000000894730440220110c55dff749806cc47390fd5824076cd3fce68e00c81993810c164a564e6573022008e3880b90b8c80680e5046126db545b9f82462712c03847dae5f623cb1e4e120140028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac81000000013564ab13000000001976a914266ae37985ef74e1d6089897639578c0c990bd0a88ac00000000

Submitting raw transaction to local node...

error code: -26
error message:
64: non-BIP68-final
64: non-BIP68-final means still time/blocked locked. You may resubmit.


------------------------------------------------------------------------------------
Example Submission 3:

λ python program.py

Running Program *** 2 ***

seconds to wait: 0, blocks to wait: 129
sequence number in little endian format: 81000000

redeem hex: 028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac
Redeem script generated P2SH addr: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp

For the P2SH address: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp found these UTXOs:

No UTXOs found. Nothing to do!

"""
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, P2shAddress, PrivateKey, PublicKey
from subprocess import Popen, PIPE
from bitcoinutils.script import Script
from binascii import hexlify
import sys
import os
import configparser
import json

#
# How far back to query for UTXOs with listtransaction with the P2SH address
#
HISTORY_TRANSACTIONS_BACK = ' 100 '
#
# When searching for Utxo, minimum amount of confirmation to seek for.
#
MIN_CONFIRMATIONS_TO_SEARCH_FOR = 1
#
# How much is expected to bloat in size after signing a transaction. Used for fees.
#
ESTIMATE_OF_PERCENTAGE_SIGNING_BLOAT_IN_TRX_SIZE = 0.8

"""
This class is used for common functionality of function 1 & 2.
"""


class Common:
    # https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki

    # Below flags apply in the context of BIP 68
    # If this flag set, nSequence is NOT interpreted as a
    # relative lock-time.
    SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)

    # If nSequence encodes a relative lock-time and this flag
    # is set, the relative lock-time has units of 512 seconds,
    # otherwise it specifies blocks with a granularity of 1.
    SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)

    # If nSequence encodes a relative lock-time, this mask is
    # applied to extract that lock-time from the sequence field. */
    SEQUENCE_LOCKTIME_MASK = 0x0000ffff

    # If this flag set, sequence is NOT interpreted as a
    # relative lock-time.
    SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)

    # Config Filename
    Configuration_File = 'program.conf'

    # Config Section for Shared values for programs
    Common_Conf_Section = 'Common'

    # Init statically the config
    config = configparser.ConfigParser()
    config.read(Configuration_File)

    @classmethod
    def get_config_value(cls, config_section, config_name):
        return cls.config[config_section][config_name]

    @classmethod
    def get_run_function(cls):
        """
        Decide whether to run function 1 or both
        """

        runFunction = cls.get_config_value(
            cls.Common_Conf_Section, "RunFunction")

        if runFunction == '1':
            return 1
        else:
            return 2

    """
    Checking for numeric goodness.
    """
    @classmethod
    def get_seconds_wait_period(cls, relative_wait_512_times_val_in_seconds_from_present):

        try:
            seconds_int = int(
                relative_wait_512_times_val_in_seconds_from_present)
        except ValueError:
            print(
                "Could not convert relative_wait_512_times_val_in_seconds_from_present to an integer.")

        return seconds_int

    """
    Checking for numeric goodness.
    """
    @classmethod
    def get_blocks_timelock_period(cls, blockslockPeriod):
        try:
            blockslockPeriod = int(blockslockPeriod)
        except ValueError:
            print("Could not convert blockslockPeriod to an integer.")

        return blockslockPeriod

    @staticmethod
    def get_int_to_little_endian_hex(intVal):
        """Converts the int sequence to hexadecimal string"""

        byteArr = (intVal).to_bytes(4, byteorder='little')
        return bytes(byteArr).hex()

    @staticmethod
    def get_pub_key_hash_from_priv_key_obj(priv_key_str):
        """
        priv key to pub hash
        """
        priv_key_obj = PrivateKey.from_wif(priv_key_str)
        pub_key_obj = priv_key_obj.get_public_key()
        pub_key_hash160 = pub_key_obj.get_address().to_hash160()
        # print("Address: ", address_hash160)
        return pub_key_hash160

    @staticmethod
    def get_pub_key_from_priv_key_obj(priv_key_str):
        """
        priv to pub key object
        """

        priv_key_obj = PrivateKey.from_wif(priv_key_str)
        pub_key_obj = priv_key_obj.get_public_key()
        return pub_key_obj

    @classmethod
    def get_CSV_Seq_Value(cls, epochlockperiod, blockslockPeriod):
        """
        bip related conversion for correct csv sequencing
        """
        # keep only the first 16 bits by stripping the rest
        epochlockperiod &= cls.SEQUENCE_LOCKTIME_MASK

        if epochlockperiod > 0:
            lock_seconds = cls.SEQUENCE_LOCKTIME_TYPE_FLAG | epochlockperiod
            # print('lock seconds: ' + str(lock_seconds))
            return cls.get_int_to_little_endian_hex(lock_seconds)

            # blocks even if zero as a default parameter to the csv script
        elif blockslockPeriod >= 0:
            blockslockPeriod &= cls.SEQUENCE_LOCKTIME_MASK
            # print('blocks to lock: ' + str(blockslockPeriod))
            return cls.get_int_to_little_endian_hex(blockslockPeriod)
        else:
            return 0

    @classmethod
    def get_csv_script(cls, seq_number_in_hex, pub_key_to_obj):
        """
        Create the locking script for P2SH
        """
        if len(seq_number_in_hex.replace('0', '')) > 0:
            # Use csv operators
            return Script([seq_number_in_hex[:4], 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP',
                           pub_key_to_obj.to_hex(),
                           'OP_DUP',
                           'OP_HASH160',
                           pub_key_to_obj.get_address().to_hash160(),
                           'OP_EQUALVERIFY',
                           'OP_CHECKSIG'])
        else:
            # Do not use csv operations
            return Script([pub_key_to_obj.to_hex(),
                           'OP_DUP',
                           'OP_HASH160',
                           pub_key_to_obj.get_address().to_hash160(),
                           'OP_EQUALVERIFY',
                           'OP_CHECKSIG'])

    @classmethod
    def get_redeem_script(cls, seq_number_in_hex, pub_key_to_obj):

        redeem_script = cls.get_csv_script(seq_number_in_hex, pub_key_to_obj)
        print('\nredeem hex: ' + redeem_script.to_hex())

        return redeem_script

    @classmethod
    def get_relative_time_seconds_blocks(cls):
        """
        Read conf wait params
        """
        relative_wait_seconds_from_present_conf = cls.get_config_value(
            cls.Common_Conf_Section, 'relative_wait_512_times_val_in_seconds_from_present')
        relative_wait_seconds_from_present_num = cls.get_seconds_wait_period(
            relative_wait_seconds_from_present_conf)
        relative_blocks_to_wait = cls.get_config_value(
            cls.Common_Conf_Section, 'relative_blocks_to_wait')
        blocks_to_wait_conf_num = cls.get_blocks_timelock_period(
            relative_blocks_to_wait)

        return (relative_wait_seconds_from_present_num, blocks_to_wait_conf_num)

    @classmethod
    def get_seq_hex_from_conf(cls, csv_args):
        """
        Compose sequence
        """
        seq_number_in_hex = cls.get_CSV_Seq_Value(
            csv_args[0], csv_args[1])

        return seq_number_in_hex

    @classmethod
    def get_redeem_script_from_conf(cls, pub_key_obj):
        """
        Great when method name are self explanatory
        """
        csv_args = cls.get_relative_time_seconds_blocks()
        seq_number_in_hex = cls.get_seq_hex_from_conf(csv_args)

        print("seconds to wait: " +
              str(csv_args[0]) + ", blocks to wait: " + str(csv_args[1]))
        print('sequence number in little endian format: ' + seq_number_in_hex)

        redeem_script = cls.get_redeem_script(seq_number_in_hex, pub_key_obj)

        to_P2SH_addr = P2shAddress.from_script(redeem_script)
        print('Redeem script generated P2SH addr: ' +
              to_P2SH_addr.to_address() + "\n")

        return redeem_script

# End of Common class. Specific function 1 or 2 functionality


def get_redeem_pub_key_obj():
    #
    # Get the private key for the p2pkh of the redeem script
    #
    # Using a public key has not been tested.
    # Support for public from user submitted text looks like it's limited in bitcoin-utils lib.
    #
    program_section = 'Function 1'

    private_key_to = Common.get_config_value(
        program_section, 'private_key_to')
    public_key_to = Common.get_config_value(
        program_section, 'public_key_to')

    if len(private_key_to) > 0:
        redeem_pub_key_obj = Common.get_pub_key_from_priv_key_obj(
            private_key_to)
        return redeem_pub_key_obj

    # Not tested and copied the line below from the lib.
    elif len(public_key_to) > 0:
        return PublicKey.from_hex(hexlify(public_key_to.to_string()).decode('utf-8'))

    else:
        sys.exit('No private or public key provided in configuration of function 1!')


def run_program_1():
    #
    # Function 1: Create redeem script
    #
    print("\nRunning Function *** 1 ***\n")

    Common.get_redeem_script_from_conf(get_redeem_pub_key_obj())


def btc_call(btc_method):
    """
    Call bitcoin-cli with a method as long as it is available in the path.
    """
    btc_client = 'bitcoin-cli '
    btcCaller = Popen(btc_client + btc_method, stdout=PIPE)
    res_line = btcCaller.stdout.read().decode('utf-8')
    return res_line.replace(' ', '').replace('\r', '').replace('\n', '')


def get_input_trx_from_utxo(priv_key_from_obj, p2sh_addr_to, seq_number_in_hex, redeem_script):
    """
    Looks back up to HISTORY_TRANSACTIONS_BACK with listtransactions to find UTXO

    Returns tuple, 0: Total Amount To Spend, 1: List of created TrxIn initialized objects 
    from UTXO.
    """
    trx_set = btc_call(
        'listtransactions *' + HISTORY_TRANSACTIONS_BACK + '0 "true"')
    json_trx_set = json.loads(trx_set)
    utxo_set = []
    total_amount = 0.0
    print("For the P2SH address: " + p2sh_addr_to + " found these UTXOs:\n")
    for trx in json_trx_set:
        if trx['address'] == p2sh_addr_to:
            # Nested if helps helps out with debugging
            if int(trx['confirmations']) >= MIN_CONFIRMATIONS_TO_SEARCH_FOR and trx['category'] == 'send':
                txin = TxInput(
                    txid=trx['txid'], txout_index=trx['vout'], sequence=seq_number_in_hex)

                print("Trx id: " +
                      str(trx['txid']) + ", vout: " + str(trx['vout']) + " amount: " + str(-trx['amount']))

                utxo_set.append(txin)
                total_amount = total_amount + (-trx['amount'])
    print("\n")
    return (total_amount, utxo_set)


def get_program2_priv_key_obj_from_conf(program2_conf_section):

    priv_key_from_str = Common.get_config_value(
        program2_conf_section, 'private_key_from')
    priv_key_from_obj = PrivateKey(priv_key_from_str)

    return priv_key_from_obj


def get_program2_p2pkh_addr_to_from_conf(program2_conf_section):

    p2pkh_addr_to_str = Common.get_config_value(
        program2_conf_section, 'P2PKH_Addr')
    p2pkh_addr_to = P2pkhAddress(p2pkh_addr_to_str)

    return p2pkh_addr_to


def get_trx_amount_fees(total_amount, trxin_set, p2pkh_addr_to_obj):
    """

    Calculate fees with approximation as to the size of the transactionself.
    Trying not introduce side effects to the harvested input transactions objects.

    """

    # set amount first without fees
    txout_just_for_size_calc = TxOutput(
        total_amount, p2pkh_addr_to_obj.to_script_pub_key())

    tx_just_for_size_calc = Transaction(
        trxin_set, [txout_just_for_size_calc])

    # https://live.blockcypher.com/btc-testnet/
    # High Priority (1-2 blocks)	Medium Priority (3-6 blocks)	Low Priority (7+ blocks)
    # 0.00059 BTC/KB 	0.00001 BTC/KB 	0.00001 BTC/KB
    trxsize_bytes = len(tx_just_for_size_calc.serialize().encode('utf-8'))
    trx_KB = (trxsize_bytes / 1024)  # * 0.00001  # Choose Medium Fee
    trx_KB *= (1 + ESTIMATE_OF_PERCENTAGE_SIGNING_BLOAT_IN_TRX_SIZE)
    trx_fees_in_btc = trx_KB * 0.00001
    total_amount = total_amount
    trx_amount = total_amount - trx_fees_in_btc

    print("Size in KB: " + str(trx_KB) + ", estimated btc fees: " +
          str(trx_fees_in_btc) + ", total amount to be transferred: " + str(total_amount) + "\n")

    return trx_amount


def trasmit_finalized_trx(signed_tx):
    #
    # Transmit transaction by submitting a process and display
    # something intelligent for the response.
    #
    submit = Common.get_config_value('Function 2', 'submit_transactions')
    if submit:
        print("\nSubmitting raw transaction to local node...\n")
        trx_id = btc_call('sendrawtransaction ' + signed_tx)
        if len(trx_id) > 0:
            print("Success or previously submitted; trx id: " + trx_id)
        else:
            print(
                "64: non-BIP68-final means still time/blocked locked. You may resubmit.")


def get_signed_trx(utxo_results, p2pkh_addr_to_obj, priv_key_from_obj, redeem_script):
    """
    Gather related data and generate
    the single transation that transfers the btc value of the
    found UTXO transactions.
    """
    trx_amount_minus_fees = get_trx_amount_fees(
        utxo_results[0], utxo_results[1], p2pkh_addr_to_obj)

    txout = TxOutput(trx_amount_minus_fees,
                     p2pkh_addr_to_obj.to_script_pub_key())

    tx = Transaction(utxo_results[1], [txout])

    # sign input trx
    for vin, txin in enumerate(utxo_results[1]):
        sig = priv_key_from_obj.sign_input(tx, vin, redeem_script)

        # set the scriptSig(unlocking script)
        txin.script_sig = Script(
            [sig, redeem_script.to_hex()])

    return tx.serialize()


def create_spending_signed_trx(p2pkh_addr_to_str, priv_key_from_obj):
    """
    Gather related data and generate
    the single transation that transfers the btc value of the
    found UTXO transactions.

    """

    p2pkh_addr_to_obj = P2pkhAddress(p2pkh_addr_to_str)

    seq_number_in_hex = Common.get_seq_hex_from_conf(
        Common.get_relative_time_seconds_blocks())

    redeem_script = Common.get_redeem_script_from_conf(
        get_redeem_pub_key_obj())

    p2sh_paid_to_addr = P2shAddress.from_script(redeem_script).to_address()

    utxo_results = get_input_trx_from_utxo(priv_key_from_obj,
                                           p2sh_paid_to_addr, seq_number_in_hex, redeem_script)

    # No sense in creating a transaction with 0 UTXOs
    if utxo_results[0] > 0 and len(utxo_results[1]) > 0:

        signed_tx = get_signed_trx(utxo_results, p2pkh_addr_to_obj,
                                   priv_key_from_obj, redeem_script)

        # print raw signed transaction ready to be broadcasted
        print("\nSigned raw transaction:\n" + signed_tx)

        trasmit_finalized_trx(signed_tx)

    else:
        print("\nNo UTXOs found. Nothing to do!\n")


def run_program_2():
    """
    Function 2
    """
    print("\nRunning Function *** 2 ***\n")
    program2_conf_section = 'Function 2'

    priv_key_from_obj = get_program2_priv_key_obj_from_conf(
        program2_conf_section)

    p2pkh_addr_to_str = Common.get_config_value(
        program2_conf_section, 'P2PKH_Addr_To')

    create_spending_signed_trx(p2pkh_addr_to_str, priv_key_from_obj)


def main():
    setup('testnet')

    which_program = Common.get_run_function()
    if which_program == 1:
        run_program_1()
    else:
        run_program_2()


if __name__ == "__main__":
    main()
