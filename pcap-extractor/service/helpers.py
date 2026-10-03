import yaml

_original_represent = yaml.SafeDumper.represent_str


def _str_repr(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return _original_represent(dumper, data)


def configure_yaml():
    yaml.add_representer(str, _str_repr, Dumper=yaml.SafeDumper)
