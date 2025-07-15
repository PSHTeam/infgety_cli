# Infgety CLI — Database Management Tool

![Bash ≥ 4](https://img.shields.io/badge/Bash-4%2B-4EAA25?logo=gnubash&logoColor=white) 
![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)

Infgety CLI is a simple, cross‑platform command‑line utility to:

- Encrypt Dart source files  
- Package Infgety‑ready databases  
- Scaffold new Infgety‑compatible projects  

It’s designed for developers who publish phone‑directory databases for use in the Infgety mobile app.

---

## 📋 Prerequisites

- **Bash 4 or higher**  
- **Dart SDK** (if you intend to encrypt or scaffold Dart files)  
- **zip** (for packaging archives)  
- On **Windows**, use **WSL 2** or **Git Bash**

---

## 📦 Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/PSHTeam/infgety_cli.git
cd infgety_cli
chmod +x infgety-cli.sh
```

Optionally, add it to your `$PATH`:

```bash
sudo ln -s "$(pwd)/infgety-cli.sh" /usr/local/bin/infgety
```

---

## 🚀 Quick Start

1. **Create a new database project**

   ```bash
   infgety create --template database --output ./my_database --id com.example.database
   ```
   This generates a directory structure under `./my_database`:
   ```
   my_database/
   ├── bin/
   │   ├── db.json
   │   ├── install.dart
   │   └── fetch_contacts.dart
   ├── lib/
   │   ├── on_install.dart
   │   └── on_fetch_contacts.dart
   ├── l10n/
   │   └── en.arb
   ├── README.md
   └── pubspec.yaml
   ```

2. **Package for production**

   ```bash
   infgety archive --database ./my_database --output ./dist
   ```
   The above command creates:
   ```
   dist/com.example.database.zip
   ```

3. **Test your package**

   1. Open the Infgety app on your device.
   2. Choose “Add New Database” and select the zip file you just created.
   3. Verify that phone numbers can be searched correctly (data lives in `./my_database/bin/db.json`).

---

## ⚙️ Command Reference

### Create

Scaffold a new project.

```text
infgety create --template database --output <dir> --id <identifier> [--verbose]
```

Generates a Dart console package pre‑wired for Infgety, including:

* `bin/install.dart` & `bin/fetch_contacts.dart`
* `bin/db.json` sample data
* `lib/` hooks (`on_install.dart`, `on_fetch_contacts.dart`)
* `l10n/en.arb`
* `pubspec.yaml` populated with your identifier


| Option                  | Description                             |
|-------------------------|-----------------------------------------|
| `--template <name>`     | Scaffold template (`database` \| `app`) |
| `--output <dir>`        | Output directory                       |
| `--id <reverse‑domain>` | Unique project identifier              |

### Archive

Package your database into a `.zip` file.

```text
infgety archive --database <dir> [--id <identifier>] [--output <dir>] [--encrypt] [--sign] [--verbose]
```

**Mandatory layout**

```
my_database/
├── bin/
│   ├── db.json
│   ├── install.dart
│   └── fetch_contacts.dart
├── lib/
│   ├── on_install.dart
│   └── on_fetch_contacts.dart
├── l10n/ # ≧ 1 *.arb
│   └── en.arb
├── README.md # optional
└── pubspec.yaml
```

If any piece is missing, archiving aborts with an error.

| Option | Description |
|--------|-------------|
| `--database` | Root directory of the database to package. |
| `--id`       | Bundle identifier *(defaults to `infgety.identifier` or `name` in `pubspec.yaml`)*. |
| `--output`   | Destination folder for the generated ZIP (`.` by default). |
| `--encrypt`  | Encrypt all Dart sources **and** wrap keys in RSA. |
| `--sign`     | Generate **SHA‑256** signatures (requires `--encrypt`). |
| `--verbose`  | Show archive composition and final size. |

### Encrypt

AES‑256‑CBC encryption

```text
infgety encrypt [--file <path> | --dir <path>] --key <32‑char UTF‑8 | 64‑char HEX> --iv  <32‑char HEX> [--key-format utf8|hex] [--recursive|--no-recursive] [--verbose]
```

| Option | Description |
|--------|-------------|
| `--file`      | Encrypt a single `.dart` file (creates `<name>.dart.enc`). |
| `--dir`       | Encrypt every `.dart` file in a directory (respects recursion). |
| `--key`       | 256‑bit AES key (UTF‑8 → 32 chars **or** HEX → 64 chars). |
| `--iv`        | 128‑bit IV (HEX → 32 chars). |
| `--key-format`| `hex` (default) or `utf8` to declare `--key` format. |
| `--recursive` | Recurse into sub‑directories (default ✔). |
| `--no-recursive` | Limit search to the top directory. |
| `--verbose`   | Print detailed operations and file sizes. |

---

## 🆘 Troubleshooting

| Symptom | Fix |
|---------|-----|
| `openssl: command not found` | Install OpenSSL and ensure it’s on `$PATH`. |
| `Error: Hex key must be exactly 64 hexadecimal characters` | Verify key length and characters (`0‑9`, `a‑f`). |
| `jq: command not found` | Install [`jq`](https://stedolan.github.io/jq/). |
| `zip: command not found` | Install `zip` utility. |
| Archive command complains about missing files | Confirm required directories/file names (see layout). |

---

## 📄 License

This project is **MIT‑licensed**. See the [LICENSE](https://github.com/PSHTeam/infgety_cli/blob/main/LICENSE) file for details.
