# TagScan

Experimental service to effectively match tags using regex patterns.

It's intended as a complementary service to the TagCheck, with the following differences:

* every rule matches a single tag (no checks for tag combinations)
* every rule is a regex pattern
* results highlight the matched tag, allowing also for safelisting

The regex patterns have to follow the syntax of [Hyperscan](https://github.com/intel/hyperscan)/[Vectorscan](https://github.com/VectorCamp/vectorscan).

A rule is a YAML document with the following fields:

```yaml
name: <name> # name of the rule
pattern: <regex> # regex pattern to match
tag: <tag> # tag to match
heuristic: <heuristic> # heuristic of the rule (optional, default is TL3 - the same set as in TagCheck)
meta:
    description: <description> # description of the rule (optional)
    category: <category> # category of the rule (optional)
    # additional metadata (optional)
```

Some docs about hyperscan vs. re2:

https://www.intel.com/content/www/us/en/collections/libraries/hyperscan/regex-set-scanning-hyperscan-re2set.html
https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/

