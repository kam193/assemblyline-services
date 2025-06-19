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
exclude_files: <regex> # standard regex to exclude matches based on filename (optional)
not: # list of standard regexes to reject a match (optional)
    - <regex1>
    - <regex2>
meta:
    description: <description> # description of the rule (optional)
    category: <category> # category of the rule (optional)
    # additional metadata (optional)
```

Fields `exclude_files` and `not` will be evaluated using the standard `re` module. It makes them
slower, but allows using features like backtracing which are not available in performance-optimized
evaluators. However, this also means they should be used very carefully to keep the overall performance.

Any metadata with "." will be set as tag.

Some docs about hyperscan vs. re2:

https://www.intel.com/content/www/us/en/collections/libraries/hyperscan/regex-set-scanning-hyperscan-re2set.html
https://rust-leipzig.github.io/regex/2017/03/28/comparison-of-regex-engines/

