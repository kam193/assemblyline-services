import yaml

HEURISTICS_MAP = dict(
    info=1,
    technique=2,
    exploit=3,
    tool=4,
    malware=5,
    safe=6,
    tl1=7,
    tl2=8,
    tl3=9,
    tl4=10,
    tl5=11,
    tl6=12,
    tl7=13,
    tl8=14,
    tl9=15,
    tl10=16,
)

_original_represent = yaml.SafeDumper.represent_str


def _str_repr(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return _original_represent(dumper, data)


def configure_yaml():
    yaml.add_representer(str, _str_repr, Dumper=yaml.SafeDumper)
