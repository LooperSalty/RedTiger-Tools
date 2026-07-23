# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.
#
# RedTiger plugin: Hash Toolkit
# Offline hash utility: identify a hash type, crack a hash against a wordlist,
# or generate a hash from plaintext. Uses only the standard-library hashlib.

from Config.Utils import *

# Hex length -> candidate algorithms.
LENGTH_TO_ALGOS = {
    32:  ["md5", "md4", "ntlm"],
    40:  ["sha1", "ripemd160"],
    56:  ["sha224", "sha3_224"],
    64:  ["sha256", "sha3_256", "blake2s"],
    96:  ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512", "blake2b"],
}
GENERATE_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
CRACK_ALGOS    = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
IS_HEX         = re.compile(r"^[0-9a-fA-F]+$")


def HashText(text, algorithm):
    try:
        digest = hashlib.new(algorithm)
        digest.update(text.encode("utf-8", "ignore"))
        return digest.hexdigest()
    except (ValueError, TypeError): return None


def IdentifyHash(data):
    data = data.strip()
    if not IS_HEX.match(data): return []
    return LENGTH_TO_ALGOS.get(len(data), [])


def CrackHash(target_hash, wordlist_path, algorithms):
    target_hash = target_hash.strip().lower()
    tested      = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                word = line.rstrip("\r\n")
                if not word: continue
                tested += 1
                for algorithm in algorithms:
                    if HashText(word, algorithm) == target_hash:
                        return word, algorithm, tested
                if tested % 100000 == 0: Wait(f"Tested {tested} candidates..")
    except (FileNotFoundError, PermissionError, OSError):
        ErrorPath()
        return None, None, tested
    return None, None, tested


def Register():
    return {
        "name"       : "Hash Toolkit",
        "description": "Identify, crack (wordlist) or generate hashes offline.",
        "function"   : Run,
        "arguments"  : {
            "mode"      : {"required": True,  "type": lambda x: x.lower(), "choices": ["identify", "crack", "generate"], "help": "Mode: identify / crack / generate"},
            "data"     : {"required": False, "type": str, "help": "The hash (identify/crack) or the plaintext (generate)"},
            "wordlist"  : {"required": False, "type": str, "help": "Wordlist file for crack mode: <path>"},
            "algorithm" : {"required": False, "type": lambda x: x.lower(), "choices": GENERATE_ALGOS, "help": "Algorithm for generate mode: " + " / ".join(GENERATE_ALGOS)},
            "output"    : {"required": False, "action": "store_true", "help": "Creating additional JSON output."},
        },
    }


def Run(mode=None, data=None, wordlist=None, algorithm=None, output=None):
    Title("Hash Toolkit")

    if not mode:
        mode = Input("Mode [-m] (identify / crack / generate) -> ").strip().lower()
    if mode not in ("identify", "crack", "generate"): ErrorMode()

    json_data = {"Parameters": {"Mode": mode}, "Informations": {}}

    if mode == "identify":
        if not data: data = Input("Hash [-d] -> ").strip()
        if not data: ErrorFormat()
        candidates = IdentifyHash(data)
        Info(f"Hash: {white}{data}")
        Info(f"Length: {white}{len(data.strip())}")
        if candidates:
            for candidate in candidates: Add(f"Possible: {white}{candidate}")
        else: Error("Unknown or non-hex hash format.")
        json_data["Parameters"]["Hash"] = data
        json_data["Informations"] = {"Length": len(data.strip()), "Candidates": candidates}

    elif mode == "crack":
        if not data: data = Input("Hash [-d] -> ").strip()
        if not data or not IS_HEX.match(data.strip()): ErrorFormat()
        if not wordlist: wordlist = Input("Wordlist [-w] -> ").strip()
        if not wordlist: ErrorPath()

        algorithms = IdentifyHash(data) or CRACK_ALGOS
        algorithms = [a for a in algorithms if a in CRACK_ALGOS] or CRACK_ALGOS
        Info(f"Hash: {white}{data}")
        Info(f"Trying algorithms: {white}{', '.join(algorithms)}")
        Wait("Cracking..")

        plaintext, matched_algo, tested = CrackHash(data, wordlist, algorithms)
        if plaintext is not None:
            Add(f"{green}Found!{white} {data} = {green}{plaintext}{white} ({matched_algo})")
        else:
            Error(f"Not found after {white}{tested}{red} candidates.")
        json_data["Parameters"].update({"Hash": data, "Wordlist": wordlist})
        json_data["Informations"] = {"Tested": tested, "Plaintext": plaintext, "Algorithm": matched_algo}

    elif mode == "generate":
        if not data: data = Input("Plaintext [-d] -> ")
        if not algorithm: algorithm = Input(f"Algorithm [-a] ({' / '.join(GENERATE_ALGOS)}) -> ").strip().lower()
        if algorithm not in GENERATE_ALGOS: ErrorMode()

        digest = HashText(data, algorithm)
        if digest is None: Error("Could not compute the hash.")
        else: Add(f"{algorithm}: {white}{digest}")
        json_data["Parameters"].update({"Algorithm": algorithm})
        json_data["Informations"] = {"Plaintext": data, "Hash": digest}

    if output in (True, None): SaveJsonToFile(json_data, f"Result_HashToolkit_{mode}", json_output=output)
    Continue()
    Reset()
