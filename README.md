# Distributed Network Measurement Protocol (DNMP), ndn-ind library version

This repository is for a project that is no longer active. It provided a foundation for aspects the on-going DCT work and was referenced in a publication, so remains up for now.

This repository is for releases of  DNMP that use the ndn-ind library ([https://github.com/operantnetworks/ndn-ind](https://github.com/operantnetworks/ndn-ind)).  This in-progress work  builds on the proof-of-concept code developed under NIST SBIR 70NANB18H186 and makes use of Pollere's Versatile Security and Bespoke Transport projects. The current release doesn't have the full run-time security code included as parts of it are still being tested.

DNMP has client and NOD (network observer daemon) processes that use NDN to communicate. Clients request measurements from NODs which use probe functions to gather metrics. The communication model is pub/sub, implemented by a lightweight pub/sub transport, syncps, and the DNMP-specific shim code.

Currently, all the metrics are gathered by sending interests to the local forwarder; but a new metric is under development that requires some patches to NFD code. The trust schema integration into the bespoke transport modules is under development. (More about DNMP, VerSec, and Bespoke Transport model in *Lessons Learned Building a Secure Network Measurement Framework using Basic NDN*, ACM ICN September, 2019 and see[http://pollere.net/Pdfdocs/ICN-WEN-190715.pdf](http://pollere.net/Pdfdocs/ICN-WEN-190715.pdf) and [https://vimeo.com/354013644](https://vimeo.com/354013644) )

## Build notes

With all the libraries installed, type "make". Works on Macs and Linux and multicast strategy uses IP multicast so only one copy of a command goes out on broadcast meda (e.g. WiFi). Note that this should have NFD patches to run properly (without them, it should run, but will be slow). Use the *no-nacks-on-multicast-faces* and s*hip-pending-interests-on-register* patches at [https://github.com/pollere/NDNpatches](https://github.com/pollere/NDNpatches) for broadcast performance.

## Using DNMP

The host must be running an NDN Forwarding Daemon. Then start a *nod* (no arguments). Clients are run from the command line, eg:

getStatus -p *probeType* -a *probeArgs* -t *target* -c *request_count*  -i *request_interval*

where getStatus is a client that runs from the command line and can request NFD status metrics. Arguments are further documented in the code: note that probeArgs can be optional for some probeTypes and target, request count and request interval  (in seconds) have defaults (local, 1,  and 1 sec respectively) if not set.

**Current probeType list:**

```
Strategy: StrategyProbe
RIB: RIBProbe
GeneralStatus: FwdProbe
FaceStatus: FaceProbe
Pinger: echoProbe
perGS: periodicProbe, runs Forwarder Status probe periodically
```

**Example usage:**

```
getStatus -p Pinger -c 100
getStatus -p Pinger -t all
getStatus-p RIB 
getStatus -p ForwarderStatus 
getStatus -p ForwarderStatus -a all 
getStatus -p FaceStatus -a <face_id_number>
getStatus -p perFS -a <period_in-milliseconds>
```

The perGS probe requests the ForwarderStatus at the period intervals five times then exits. This is done from the Probe, not the Client, which has already exited so output is currently to the NOD standard output, nothing elegant but a stub for future work. 

A black hole client can be used to multicast measurement requests to non-local NODs. The specific usage is to report on whether the NOD has a prefix in its FIB or not.

```
getBH -p <prefix>
```

## Name Notes

Clients issue commands which should have ten name components appended to one or more components that identify the local network, and an empty data field. (Eventually, some of these components will go away but they are useful for debugging readability.)

| component   | description                                          |
| ----------- | ---------------------------------------------------- |
| networkID   | e.g., myHouse                                        |
| namespace   | **dnmp**                                             |
| targetType  | **nod** only current target type                     |
| nodSpec     | ids target NODs, e.g. **all**, **local**, *identity* |
| topic       | **command**                                          |
| roleType    | operator, user, or guest                             |
| ID          | role-specific identifier                             |
| origin      | the publications origin's network-attached device    |
| commandType | **probe** (may be others in future)                  |
| probeType   | e.g., NFDGeneralStatus                               |
| probeArgs   | e.g., NFibEntries, may be empty                      |
| timestamp   | current UTC at Client                                |

NODs reply to commands with fifteen name components appended to the local network components and (usually) data. Most of the fields come directly from the associated command.

| component  | description                                           |
| ---------- | ----------------------------------------------------- |
| networkID  | e.g., myHouse                                         |
| namespace  | **dnmp**                                              |
| targetType | from command                                          |
| nodSpec    | from command                                          |
| topic      | **reply**                                             |
| commandID  | and exact copy of command's last **seven** components |
| dCnt       | indicates number of Data packets of reply             |
| replyType  | **nod**                                               |
| replyID    | a nod *identity*                                      |
| timestamp  | current UTC at NOD                                    |
