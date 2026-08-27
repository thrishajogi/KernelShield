# KernelShield

## Overview

**KernelShield** is a kernel-level runtime security project designed to monitor Linux processes and detect suspicious runtime behavior using **eBPF**.

It observes process execution and network activity, correlates events, and assigns risk based on predefined behavioral rules.

## Key Features

* **eBPF-based runtime monitoring**
* Process execution tracking
* Network activity monitoring
* Process parent-child relationship tracking
* Behavioral risk scoring
* Suspicious server-to-shell detection
* Detection of suspicious network utilities such as:

  * `curl`
  * `wget`
  * `nc`
  * `netcat`
* Multi-stage attack-chain correlation
* Structured JSON event logging
* Runtime event display

## Detection Flow

```text
Linux Process Activity
        ↓
      eBPF
        ↓
   Event Collection
        ↓
 Process State Tracking
        ↓
 Behavioral Rules
        ↓
   Risk Scoring
        ↓
 Detection / Alert
        ↓
      Logging
```

## Example Attack Chain

```text
Server Process
      ↓
    Shell
      ↓
 Network Utility
      ↓
 Network Activity
      ↓
Suspicious Behavior
```

## Current Status

The project currently has a working build and can capture:

* `EXEC` events
* `EXIT` events
* `NETWORK` events

The detector also maintains process state and performs behavioral analysis using multiple detection rules.

## Technology Stack

* **Linux**
* **C**
* **eBPF**
* **libbpf**
* **bpftool**
* **CMake**
* **Git**

## Project Structure

```text
KernelShield/
├── src/
│   ├── detector/
│   ├── main.c
│   └── logger.c
├── include/
├── third_party/
│   └── libbpf-bootstrap/
├── logs/
├── build/
├── CMakeLists.txt
└── README.md
```

## Goal

The goal of KernelShield is to provide **runtime visibility and behavioral detection at the Linux kernel level**, enabling suspicious process activity to be identified and analyzed in real time.

