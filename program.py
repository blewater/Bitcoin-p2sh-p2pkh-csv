"""
Bitcoin script interfacing with Bitcoin core.
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

    # Config Section for Shared values for both program functions.
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
    function_section = 'Function 1'

    private_key_to = Common.get_config_value(
        function_section, 'private_key_to')
    public_key_to = Common.get_config_value(
        function_section, 'public_key_to')

    if len(private_key_to) > 0:
        redeem_pub_key_obj = Common.get_pub_key_from_priv_key_obj(
            private_key_to)
        return redeem_pub_key_obj

    # Not tested and copied the line below from the lib.
    elif len(public_key_to) > 0:
        return PublicKey.from_hex(hexlify(public_key_to.to_string()).decode('utf-8'))

    else:
        sys.exit('No private or public key provided in configuration of function 1!')


def run_function_1():
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


def get_function2_priv_key_obj_from_conf(function2_conf_section):

    priv_key_from_str = Common.get_config_value(
        function2_conf_section, 'private_key_from')
    priv_key_from_obj = PrivateKey(priv_key_from_str)

    return priv_key_from_obj


def get_function2_p2pkh_addr_to_from_conf(function2_conf_section):

    p2pkh_addr_to_str = Common.get_config_value(
        function2_conf_section, 'P2PKH_Addr')
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


def run_function_2():
    """
    Function 2
    """
    print("\nRunning Function *** 2 ***\n")
    function2_conf_section = 'Function 2'

    priv_key_from_obj = get_function2_priv_key_obj_from_conf(
        function2_conf_section)

    p2pkh_addr_to_str = Common.get_config_value(
        function2_conf_section, 'P2PKH_Addr_To')

    create_spending_signed_trx(p2pkh_addr_to_str, priv_key_from_obj)


def main():
    setup('testnet')

    which_function = Common.get_run_function()
    if which_function == 1:
        run_function_1()
    else:
        run_function_2()


if __name__ == "__main__":
    main()
