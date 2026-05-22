# Secure Client/Server Applications – Project

This project implements two secure client/server applications:

1. **CSV Secure File Sync** – A Python‑based tool that encrypts CSV files locally, exchanges a Diffie‑Hellman key, and uploads encrypted files to a server for storage and batch decryption.
2. **Secure Web App** – An Apache web server configured with two HTTPS setups: a secure modern TLS configuration and a deliberately insecure configuration (weak ciphers, old protocols) for analysis.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Application 1: CSV Secure File Sync](#application-1-csv-secure-file-sync)
  - [Server Setup](#server-setup)
  - [Client Usage](#client-usage)
- [Application 2: Secure Web App](#application-2-secure-web-app)
  - [Secure Configuration](#secure-configuration)
  - [Insecure Configuration](#insecure-configuration)
- [Testing & Packet Capture](#testing--packet-capture)
- [Team Contributions](#team-contributions)
- [References](#references)

---

## Project Structure
