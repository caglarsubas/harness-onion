"""Safe serialization for temporary META test fixtures, never product output."""
import yaml


def selected_safe_dumper():
    return getattr(yaml, "CSafeDumper", yaml.SafeDumper)


def dump_fixture(value):
    return yaml.dump(value, Dumper=selected_safe_dumper(), sort_keys=False, width=1000)

