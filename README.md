# Proxy DLL Generator

Generates a proxy DLL that forwards all exports from a legitimate DLL while executing an arbitrary command on load.

The tool parses a source DLL, recreates its export table, and builds a proxy DLL that launches a supplied command via a hidden process when the DLL is loaded.

## Overview

This tool is designed for DLL proxying / hijacking scenarios.

It:
- Detects the architecture (x86 / x64) of a source DLL
- Extracts all named exports
- Generates a `.def` file mapping exports to the original DLL
- Builds a proxy DLL using MinGW
- Executes an arbitrary command on `DLL_PROCESS_ATTACH`
- Obfuscates the command using a simple XOR encoder at compile time

The resulting DLL behaves like the original from the loader’s perspective while executing attacker-controlled code.

## How It Works

1. Parses the source DLL using `pefile`
2. Detects architecture via `OPTIONAL_HEADER.Magic`
3. Extracts all named exports
4. Writes an exports definition file forwarding calls to the real DLL
5. Generates a C stub that:
   - XOR-decodes the command at runtime
   - Launches it via `CreateProcessA` with a hidden console window
6. Compiles the proxy DLL with MinGW GCC

## Usage

```sh
ProxyDLL.py <source.dll> <output.dll> <command>
```

## Example

```sh
ProxyDLL.py source.dll proxy.dll "cmd.exe /c calc.exe"
```

Place the resulting DLL in a directory where it will be loaded instead of the original.

## Requirements

- Python 3
- `pefile`
- MinGW-w64 toolchain
  - `x86_64-w64-mingw32-gcc` for x64
  - `i686-w64-mingw32-gcc` for x86

## Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

## License

[MIT License](LICENSE)


