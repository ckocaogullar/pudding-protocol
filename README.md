# Pudding 🍮

This repository contains the code for the Pudding private user discovery protocol (paper accepted to IEEE S&P 2024, [check it out](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a167/1Ub24I5jc6A)).
In particular, it contains the following components:
- A prototype implementation that runs on the [Nym anonymity network](https://nymtech.net/)
- An evaluation harness
- A Python notebook for analysis

> [!NOTE]  
> This is an academic prototype and not fit for production use.


## Abstract 📄

Anonymity networks allow messaging with metadata privacy, providing better privacy than popular encrypted messaging applications.
However, contacting a user on an anonymity network currently requires knowing their public key or similar high-entropy information, as these systems lack a privacy-preserving mechanism for contacting a user via a short, human-readable username.
Previous research suggests that this is a barrier to widespread adoption.

In this paper we propose Pudding, a novel private user discovery protocol that allows a user to be contacted on an anonymity network knowing only their email address.
Our protocol hides contact relationships between users, prevents impersonation, and conceals which usernames are registered on the network.
Pudding is Byzantine fault tolerant, remaining available and secure as long as less than one third of servers are crashed, unavailable, or malicious.
It can be deployed on Loopix and Nym without changes to the underlying anonymity network protocol, and it supports mobile devices with intermittent network connectivity.
We demonstrate the practicality of Pudding with a prototype using the Nym anonymity network.
We also formally define the security and privacy goals of our protocol and conduct a thorough analysis to assess its compliance with these definitions.


## Setup (1h human time)

We tested our setup using a cloud-rented Ubuntu 22.04 machine with 8 CPU cores and 16 GiB Ram.

First install the basic build dependencies:

```bash
$ sudo apt update;
$ sudo apt install -y build-essential git curl;
```

Then install the `rustup` toolchain manager from [here](https://rustup.rs/).
This manager is later used by our scripts to ensure you are running the same version as we do.

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh;
$ source "$HOME/.cargo/env";
```

Then run the `prepare_and_build.sh` script. It does multiple things:
- Sets our Rust version as the default
- Download the external dependencies `nym` and `forked-nym-sphinx` to `external`
- Applies the `nym.patch` and `nym-lock.patch` to `external/nym`
- Checkouts the `pudding` branch in `external/forked-nym-sphinx`
- Builds the `pudding` code base in debug mode and tests it
- Builds the `nym` code base in release mode

```bash
$ ./prepare_and_build.sh;
```

This script might run up to 15 minutes on a modern computer.
When it finishes successfully, it outputs a positive confirmation:

```
[+] All prepared and built for the evaluation
```


## Evaluation (1h human time + 4h compute time)

All evaluation is performed by simply executing the script `run_evaluation.sh`.
The script (once more) ensures that there is a recent release build.
It then executes all scenarios from the paper (each lasting around 600 seconds).
If there are failures (e.g. gateways being flaky), each run is automatically retried up to 10 times.
To abort the script, send `CTRL+C` twice.

All output is collected in the `/output` folder and prefixed by a datetime string based on when the script is started.
You will find some sample output zipped in that folder when you checkout this repository.
In that case simply run `cd output/ && unzip sample.zip`.

You can increase the number of times each scenario is executed by changing the line `for round in {1..2}; do` in the script.
For instance, you might replace `2` with `10` to run each scenario 10 times.
By default we set it to `2` in this repository as it provides a good trade-off between compute time and stable results.

On a Hetzner CPX41 machine (8 CPU cores, 16 GiB RAM), the evaluation takes around 4 hours.
This is the output when monitoring using the `time` command:

```
$ /usr/bin/time -v ./run_evaluation.sh

[...]

        Command being timed: "./run_evaluation.sh"
        User time (seconds): 19281.80
        System time (seconds): 1116.46
        Percent of CPU this job got: 188%
        Elapsed (wall clock) time (h:mm:ss or m:ss): 3:00:00
        Average shared text size (kbytes): 0
        Average unshared data size (kbytes): 0
        Average stack size (kbytes): 0
        Average total size (kbytes): 0
        Maximum resident set size (kbytes): 149288
        Average resident set size (kbytes): 0
        Major (requiring I/O) page faults: 0
        Minor (reclaiming a frame) page faults: 416201
        Voluntary context switches: 64384711
        Involuntary context switches: 133603
        Swaps: 0
        File system inputs: 0
        File system outputs: 83728
        Socket messages sent: 0
        Socket messages received: 0
        Signals delivered: 0
        Page size (bytes): 4096
        Exit status: 0
```

## Analysis (1h human time)

The evaluation is done using Python notebooks within the `evaluation` folder.
Since we use the Python notebooks interactively, we suggest you copy the `output` folder back onto your local machine and perform the steps there.

First we install the required dependencies using `venv` and `pip`:

```bash
$ sudo apt install python3 python3-venv python3-pip
$ cd analysis
$ python3 -mvenv env
$ source env/bin/activate
(venv) $ python3 -mpip install -r requirements.txt
```

Then we can start the Jupyter notebook server:

```bash
(venv) $ jupyter notebook
```

Open the `evaluation.ipynb` notebook and find the line with the datetime prefix.
Edit it to match the prefixes from your run.
Then execute the entire notebook.
It will generate all the plots and tables from the paper.
You can find the generated figure files in the `analysis/figures` folder.


## Bibtex 📚

TBD once published.
