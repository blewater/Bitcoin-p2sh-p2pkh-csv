## __Create__ and __Redeem__ Bitcoin P2SH wrapped P2PKH transaction with a relative CSV timelock. ##

### Main Functions ###

**1.** Create a P2SH address where all funds sent to it should be locked for N time(*) after its creation; other than the time locking part the redeem script is equivalent to a P2PKH transaction. Thus it generates a P2SH wrapped P2PKH transaction.

<details>
<summary>(*) Supports relative time delays of both blocks or seconds:</summary>
Seconds 128 * 512 blocks of time. The wait configuration value of 0 allows for immediate successful submission.</details>

**2.** Spend the funds from the generated P2SH address. Find the UTXOs paid to a P2SH address and transfer their Bitcoin value to the target P2PKH_Addr_To addresss.

__Precondition: bitcoin-cli needs to in the path otherwise, this humble deliverable can't find utxo or submit transactions.__

Configuration is provided in program.conf. See configuration comments for details.

Both functions 1 and 2 run from the same script: *python program.py*
If the configuration value RunFunction == **1**, then only the redeem script gets created. For RunFunction value == **2, both functions 1 and 2's functionality run.

_You may run it in the same path with program.conf_

`python program.py`

This scripts has been tested with bitcoin node 13.1 in ubuntu, 13.2 windows.

It works for single and multiple input UTXO transactions.

------------------------------------------------------------------------------------
#### Example Submission 1: ####

`λ python program.py`

    Running Function *** 2 ***

    seconds to wait: 0, blocks to wait: 0
    sequence number in little endian format: 00000000

    redeem hex:                 2103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac
    Redeem script generated P2SH addr: 2NFbu9tEGnLKZYQtxNgiA7DSeN61hDe9SkA

    For the P2SH address: 2NFbu9tEGnLKZYQtxNgiA7DSeN61hDe9SkA found these UTXOs:

    Trx id: d2c9a1fe7164b7525670ad76588092454751e29f8234e76a67875f96331bc0a4, vout: 0 amount: 1.1


    Size in KB: 0.298828125, estimated btc fees: 2.9882812500000002e-06, total amount to be transferred: 1.1


    Signed raw transaction:
    0200000001a4c01b33965f87676ae734829fe251474592805876ad705652b76471fea1c9d2000000008447304402205f1bf7918f70b0c82bf495309a3c104d8d3a3edc7789b79537b8419eb322dcc6022017ea79a4007502d4de305112b91293a4b2e336fb00535509b39038112d141406013b2103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac000000000155768e06000000001976a914266ae37985ef74e1d6089897639578c0c990bd0a88ac00000000

    Submitting raw transaction to local node...

    Success or previously submitted; trx id: 4a48c21046b8e068ccfc992b14031f9cdc536ea1a3bd82a1cf411b85774943bc

------------------------------------------------------------------------------------
 #### Example submission 2: ####

`λ python program.py`

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
#### Example Submission 3: ####

`λ python program.py`

    Running Program *** 2 ***

    seconds to wait: 0, blocks to wait: 129
    sequence number in little endian format: 81000000

    redeem hex: 028100b2752103815c6a6e52bc6d05e6678c313a3495e877050715cd9057f6be071924d28ed46076a914266ae37985ef74e1d6089897639578c0c990bd0a88ac
    Redeem script generated P2SH addr: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp

    For the P2SH address: 2NESVpGidmToyL7ZhQYmdJUdN6uLKmTMnKp found these UTXOs:

    No UTXOs found. Nothing to do!
