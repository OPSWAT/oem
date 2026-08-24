"""
Configuration file support.

Precedence is code defaults, then the config file, then command-line flags -
so a config file makes a routine run a single command, while any one-off can
still be overridden on the spot without editing the file.

INI rather than JSON because a config an operator edits should be able to carry
comments explaining each setting, and configparser is in the standard library
on every version this runs on.

The file holds API keys, so keep the real one out of source control and out of
anything you share. ``mb-sweep.conf.sample`` is the template to distribute;
``mb-sweep.conf`` is the one that gets used.
"""

import configparser
import os

CONFIG_SECTION = "sweep"
DEFAULT_CONFIG_NAMES = ["mb-sweep.conf"]

# How each setting is coerced from its string form. Anything absent here is
# rejected rather than silently ignored, so a typo in the file is reported
# instead of quietly having no effect.
SETTING_TYPES = {
    # Credentials
    "api_key": str,
    "mb_key": str,
    # Corpus size
    "per_day": int,
    "malware_count": int,
    "clean_pe_count": int,
    "clean_docs": int,
    "clean_dir": str,
    # Locations
    "out_dir": str,
    "state": str,
    # Discovery
    "signatures": str,
    "tags": str,
    "file_types": str,
    "exclude_types": str,
    "query_workers": int,
    "query_limit": int,
    "max_size": float,
    # Execution
    "poll_interval": int,
    "poll_window": int,
    "delay": float,
    # Switches
    "no_av": bool,
    "no_cdr": bool,
    "no_mutate_clean": bool,
    "delete_after": bool,
    "allow_synced_dir": bool,
    "include_nested_archives": bool,
}

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def find_config(explicit, script_dir):
    """
    Work out which config file to read.

    An explicit ``--config`` wins and must exist - failing loudly beats
    silently running with different settings than intended. Otherwise look
    beside the script, then in the working directory.
    """
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit(f"Config file not found: {explicit}")
        return explicit

    for directory in (script_dir, os.getcwd()):
        for name in DEFAULT_CONFIG_NAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def load_config(path):
    """
    Read a config file and return argparse-ready defaults.

    Returns ``{}`` when there is no file. Unknown keys raise, because a
    misspelled setting that is ignored looks exactly like a setting that did
    not work.
    """
    if not path:
        return {}

    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        raise SystemExit(f"Could not parse {path}: {exc}")

    if not parser.has_section(CONFIG_SECTION):
        raise SystemExit(
            f"{path} has no [{CONFIG_SECTION}] section - see "
            f"mb-sweep.conf.sample for the expected shape.")

    values = {}
    for key, raw in parser.items(CONFIG_SECTION):
        name = key.strip().replace("-", "_")
        if name not in SETTING_TYPES:
            raise SystemExit(
                f"{path}: unknown setting '{key}'. Valid settings are: "
                f"{', '.join(sorted(SETTING_TYPES))}")

        raw = raw.strip()
        if raw == "":
            continue        # present but blank means "leave the default alone"

        kind = SETTING_TYPES[name]
        try:
            if kind is bool:
                lowered = raw.lower()
                if lowered in TRUE_VALUES:
                    values[name] = True
                elif lowered in FALSE_VALUES:
                    values[name] = False
                else:
                    raise ValueError(raw)
            else:
                values[name] = kind(raw)
        except ValueError:
            raise SystemExit(
                f"{path}: setting '{key}' expects "
                f"{'true/false' if kind is bool else kind.__name__}, "
                f"got '{raw}'")

    return values


def describe_source(path, values):
    """A one-line note about what the config contributed, for the console."""
    if not path:
        return "no config file found; using built-in defaults"
    hidden = {"api_key", "mb_key"}
    named = sorted(k for k in values if k not in hidden)
    keys_present = sorted(k for k in values if k in hidden)
    parts = []
    if keys_present:
        parts.append(f"{len(keys_present)} key(s)")
    if named:
        parts.append(f"{len(named)} setting(s): {', '.join(named)}")
    return f"{path} ({'; '.join(parts) if parts else 'nothing set'})"
