from dataclasses import dataclass

import tlsh

BADLIST_QUERY = "hashes.tlsh:* AND enabled:true"

@dataclass
class TLSHData:
    hash: tlsh.Tlsh
    reference: str

    def get_distance(self, hash: tlsh.Tlsh):
        return self.hash.diff(hash)

    def __hash__(self):
        return hash(self.hash)
