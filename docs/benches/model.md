# Benchmarking

Prior to this work, we had multiple implemented schemes that lacked practical performance comparision. We came up with two approaches that rely on Criterion to measure the computation time.
To provide fair measurements of the implemented schemes, we allow the comparison of schemes with similar functionalities under the same invariant: the security level, a.k.a. the **maximum number of malicious parties**. For the same maximum number of malicious parties, different schemes may require different numbers of active participants.

First, we cared about measuring how much time each scheme takes to complete end-to-end when being run with all the participants together. We call such measuring techniques the "naive technique". In fact, implementating this technique is fairly quick but the benchmarks are not 100% reliable. We discuss in the next section what this technique is about and why it is considered “naive”.

Next we brainstormed and implemented a more representative approach that utilizes a more "advanced technique" based on snapshotting the communication then replaying the protocol with a single participant using the snapshot. This technique allowed us to measure the basic computation time per participant and include network latency and the size of data sent over the wire.

If interested only in the advanced benchmarking technique, please skip to section [Advanced Technique](#advanced-technique)

## Naive Technique

A quick solution to benchmark our schemes is to run the entire protocol for all the participant (side-by-side) and analyse the results.
We consider this benchmarking technique to be naive for several reasons:

1. It runs multiple participants in a sequential manner which combines with the quadratic/cubic nature of some of the protocols, preventing us from having a clear idea about each participant's computation time and representing network latency.

2. Combining running the participants sequential with having different signature schemes requiring different number of active participant (for the same maximum number of malicious parties) might create a bias in comparing the results across schemes.

3. A participant sending one message to all implies measuring the same send operation multiple time.

The table below shows running the criterion tests for the Robust ECDSA and OT-Based ECDSA schemes when fixing the maximum number of malicious parties to 6 participants.
One can see that the Robust ECDSA scheme seems much more performant than the OT-based ECDSA.

<center>

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 7 | 877.19 ms  | 886.42 µs | 115.73 µs |
| **Robust ECDSA**   | 13 | N/A       | 30.117 ms | 170.91 µs |

| **Maximum number of malicious parties: 6** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

*Note: These results reflect sequential protocol runs across all participants and should be interpreted with caution.*

</center>

## Advanced Technique

An accurate way to benchmark a protocol is by using the snap-then-simulate method: Instead of benchmarking the protocol run with all the participants included, we run the protocol including only two participants where only one  of them is real and the other is simulated. The real participant is the coordinator (where possible), and the simulated participant is the entire environment.
The real participant interacts with the simulation of the other parties.

More specifically, we first allowed the derandomization of the algorithms to benchmark. Then we implemented `run_protocol_and_take_snapshots` function which runs a specific protocol with all of it participants and stores in a dictionary the messages sent among the participants. Next we implemented the logic of what a simulator is and the function `run_simulated_protocol` allowing the simulator to reply in a dummy fashion to a real participant using the snapshot storage. It is essential to preserve the same order of messages sent during snapshot and simulation to be able to reproduce the same messages sent by the real participant twice (of course the same randomness is used twice for the real participant).
During the second (simulated) run, we benchmark the real participant's performance using Criterion. We also allowed adding latency discussed in section [Latency & Bandwith](#latency-and-bandwidth) and were able to measure the size of data received per participant during a protocol run.

### Why is this technique better than naive one?

1. Fair benchmarking of the different protocols: even when requiring more participants for one scheme, the benchmarking would focus on the actual performance of a single real participant instead of all participants.

2. Better representation of $O(n^2)$ communication protocol: simulating all-but-one participants would translate the protocol from $O(n^2)$ to $O(n)$ which makes the benchmarking way more focused on a single participant and avoiding the complexity of communication between the simulated participants

3. Better handling of the network latency: we can now add a wait at the reception of a message by the simulated participant. This can be tuned on demand reflecting variable network latency. This would reflect quite accurately the performance of different protocols that vary in the number of communication rounds.

4. Easy way to compute the size of data transmitted on the wire.

### Results & Analysis

In this section, we present a couple of results. The two following tables represent the time required by a single participant (coordinator if applicable) to complete a protocol. The numbers are, as expected, computed using the advanced benchmarking technique.

<center>

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 7 | 203.46 ms  | 206.88 µs | 110.41 µs |
| **Robust ECDSA**   | 13 | N/A       | 4.9369 ms | 113.22 µs |

| **Maximum number of malicious parties: 6** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

<br>

</center>

With a larger number of accepted malicious parties, the numbers are as follows:

<center>

| Scheme | Parties | Two Triples Gen | Presign | Sign |
|:------:|:-------:|-----------:|--------:|-----:|
| **OT based ECDSA** | 16 | 544.94 ms  | 257.05 µs | 119.65 µs |
| **Robust ECDSA**   | 31 | N/A       | 24.562 ms | 129.45 µs |

| **Maximum number of malicious parties: 15** | **Network Latency: 0 ms** |
|---------------------------------------------|----------------------------|

</center>

#### Latency and Bandwidth