# AutoSeed - Vanity Address Generator

A high-performance vanity address generator for the Autonomys network and other Substrate-based chains, capable of creating custom addresses with specific patterns.

## Features

- **Multi-threaded** - Utilizes all CPU cores for maximum performance
- **Multi-Network Support** - Generate addresses for Autonomys, Polkadot, Substrate, or any custom SS58 prefix
- **Flexible Pattern Matching** - Search for patterns as prefix or suffix with customizable position constraints
- **Two Generation Modes**:
  - **Mnemonic Mode** - Traditional 12-word seed phrases (slower but universally compatible)
  - **Hex Mode** - Direct private key generation in hex format (faster, saves as Polkadot.js/Talisman compatible encrypted JSON)
- **Real-time Statistics** - Live progress tracking with ETA and luck factor
- **Case-sensitive/insensitive** - Flexible pattern matching options
- **Wildcard Support** - Use `?` to match any character
- **Automatic Wallet Saving** - Saves results to organized directory structure

## Installation

### Download Precompiled Binary

The easiest way to get started is to download a precompiled binary from the [releases page](https://github.com/vexr/autoseed/releases).

### Build from Source

#### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git

#### Clone and Build

```bash
# Clone the repository
git clone https://github.com/vexr/autoseed.git
cd autoseed

# Build for production (highly optimized binary)
cargo build --release

# The optimized binary will be at: ./target/release/autoseed
```

### Build Optimizations

For maximum performance, build with the following optimizations:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

This enables CPU-specific optimizations for your machine.

## Usage

### Basic Usage

```bash
# Generate an address with "ai3" pattern at the end (default suffix mode, Autonomys network)
./autoseed

# Search for custom pattern at the end
./autoseed --term "cool"

# Use hex mode for faster generation
./autoseed --term "fast" --hex

# Generate for different networks
./autoseed --term "dot" --network Polkadot
./autoseed --term "sub" --network Substrate
./autoseed --term "test" --ss58-prefix 999
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--term <PATTERN>` | `-t` | Pattern to search for in addresses | `ai3` |
| `--count <COUNT>` | `-c` | Number of wallets to generate | `3` |
| `--hex` | `-h` | Use hex mode for faster generation | `false` |
| `--network <NETWORK>` | `-n` | Network to generate addresses for (Autonomys, Polkadot, Substrate) | `Autonomys` |
| `--ss58-prefix <PREFIX>` | | Custom SS58 prefix number (alternative to --network) | N/A |
| `--threads <COUNT>` | `-T` | Number of CPU threads to use | Number of CPU cores |
| `--within <N>` | `-w` | Find pattern within the first N characters (prefix mode) or last N characters (suffix mode) | Term length (suffix), `5` (prefix) |
| `--prefix` | `-p` | Search for pattern at the start of address (after network prefix) | `false` (suffix mode) |
| `--suffix` | `-s` | Search for pattern at the end of address | `true` (default) |
| `--anywhere` | `-a` | Search for pattern anywhere in the address | `false` |
| `--case-sensitive` | `-C` | Enable case-sensitive pattern matching | `false` |
| `--output-dir <DIR>` | `-o` | Directory to save generated wallets | `./wallets/` |
| `--pass <PASSWORD>` | | Password for encrypting wallets (non-interactive mode) | Interactive prompt |
| `--probability` | `-P` | Show detailed probability calculations and expected attempts | `false` |

**Note**: `--network` and `--ss58-prefix` are mutually exclusive - use one or the other, not both.

### Examples

```bash
# Generate 10 addresses with "moon" pattern at the end using 8 threads
./autoseed --term "moon" --count 10 --threads 8

# Short form: Search for "dao" at the end with hex mode
./autoseed -t "dao" -h

# Case-sensitive search with wildcards at the end
./autoseed -t "Ai?" -C

# Find pattern at the start of address within first 10 characters (prefix mode)
./autoseed --term "web3" --prefix --within 10

# Search for pattern anywhere in the address
./autoseed -t "cool" -a

# Generate Polkadot addresses with "dot" at the end
./autoseed --term "dot" --network Polkadot --count 3

# Generate for custom network using SS58 prefix
./autoseed --term "test" --ss58-prefix 42 --hex

# Non-interactive mode with password
./autoseed --term "secure" --hex --pass "mypassword123"

# Show probability calculations for a difficult pattern
./autoseed -t "hello" -P -c 1

# Mix of short and long options
./autoseed -t "web3" -c 5 -h -T 16 -o ./my-wallets/
```

## Supported Networks

The generator supports multiple Substrate-based networks:

| Network | SS58 Prefix | Address Starts With | Example |
|---------|-------------|---------------------|---------|
| **Autonomys** (default) | 6094 | `su` | `sueC91W98mWabwxBig1UaZCFCMagkoBUpP2n7XBG7nchronos` |
| **Polkadot** | 0 | `1` | `15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5` |
| **Substrate** | 42 | `5` | `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY` |
| **Custom** | Any number | Various | Use `--ss58-prefix <number>` |

**Note**: Networks can be configured with multiple address prefixes. For example, Autonomys could potentially use prefixes like `su`, `sub`, `suc`, or `sue` - the system supports validation for any combination of prefixes per network.

### Network Selection

```bash
# Use predefined networks
./autoseed --term "dot" --network Polkadot
./autoseed --term "sub" --network Substrate
./autoseed --term "ai3" --network Autonomys  # default

# Use custom SS58 prefix for any Substrate network
./autoseed --term "test" --ss58-prefix 999
```

## Generation Modes

### Mnemonic Mode (Default)

- Generates standard 12-word BIP39 mnemonic phrases
- Compatible with all Substrate wallets
- Slower generation speed
- Saves mnemonics as `.txt` files

```bash
./autoseed --term "lucky"
```

Output:
```
Address: su...KtgqCYhPa6kqPf1K8V9mPL2MXjhqLucky
Mnemonic: vendor shuffle viable duck observe wing follow barely...
```

### Hex Mode (--hex)

- Generates raw 32-byte private keys (displayed as hex string)
- Faster than mnemonic mode
- Requires password for encryption
- Saves as Polkadot.js/Talisman compatible encrypted JSON files

```bash
./autoseed --term "fast" --hex --count 5
```

Output:
```
Address: su...KfBbR9nYGwmKtgqCYhPa6kqPf1K8V9mPL2MXfast
Private Key: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

**Important**: With hex mode, you MUST:
- Remember your encryption password (no recovery possible)
- Keep the JSON files safe (they contain your encrypted private keys)
- Import using the JSON file + password in Polkadot.js, Talisman, or other compatible wallets

## Performance Comparison

| Mode | Speed | Security | Compatibility |
|------|-------|----------|----------------|
| Mnemonic | Baseline | Standard BIP39 | Universal |
| Hex | Faster | Encrypted JSON | Polkadot.js/Talisman |

## Understanding the Statistics

During generation, you'll see real-time statistics:

```
Attempts: 125,420 · Speed: 2,508 keys/s · Runtime: 00:50 · ETA: ~2m 15s · Luck: 73%
```

- **Attempts**: Total addresses checked
- **Speed**: Current generation rate
- **Runtime**: Time elapsed
- **ETA**: Estimated time to find match (based on expected attempts)
- **Luck**: Your luck factor (100% = exactly as expected, <100% = taking longer than expected, >100% = found faster than expected)

**Note on Luck Calculation**: Luck is calculated using the mathematical expected value (mean) as the baseline. If a pattern has an expected difficulty of 1,000,000 attempts and you find it in 500,000 attempts, your luck is 200% (twice as lucky as expected). Over many wallet generations, the average luck should approach 100%.

## Pattern Matching

Address prefixes depend on the network selected:

- **Autonomys**: Addresses start with "su" 
- **Polkadot**: Addresses start with "1"
- **Substrate**: Addresses start with "5"
- **Custom**: Varies based on SS58 prefix

When searching:

- **Suffix mode (default)**: Pattern appears at the end of the address
- **Prefix mode**: Pattern appears after the network prefix (e.g., after "su" for Autonomys)
- **Wildcards**: Use `?` to match any character (e.g., "a?3" matches "ai3", "ab3", etc.)
- **Within**: Constrains pattern to appear within N characters from start (prefix) or end (suffix)

## Output Structure

Generated wallets are saved in the output directory:

```
wallets/
├── suABC123...txt          # Autonomys mnemonic mode
├── suXYZ789...json         # Autonomys hex mode (encrypted)
├── 1DEF456...txt           # Polkadot mnemonic mode
├── 5GHI789...json          # Substrate hex mode (encrypted)
└── ...
```

## Building from Source

### Development Build
```bash
cargo build
```

### Production Build (Recommended)
```bash
cargo build --release
```

### With Native CPU Optimizations
```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Safety & Security

- Never share your mnemonic phrases or JSON passwords
- Store encrypted JSON files securely (they contain your private keys)
- Test wallet recovery before storing significant funds
- The generation process is cryptographically secure using OS random number generation

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created by vexr for the Autonomys Network community

Feel free to reach out on Discord: [https://autonomys.xyz/discord](https://autonomys.xyz/discord)