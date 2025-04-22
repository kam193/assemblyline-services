# Simple-Downloader

Very simple service to download URLs, without running a whole browser.
In addition, it can extract URLs from directory listings as URI files allowing to download automatically download them.

## Request parameters

| Name                             | Type | Description                                          | Default                |
| -------------------------------- | ---- | ---------------------------------------------------- | ---------------------- |
| user_agent                       | str  | User agent to use for the request                    | python-requests/2.25.0 |
| extract_dir_listing_as_urls      | bool | Extract URLs from directory listing to download them | false                  |
| extract_directories_from_listing | bool | Extract directories from directory listing           | false                  |
| extraction_depth                 | int  | Maximum depth to extract from directory listing      | 1                      |
| proxy                            | str  | Proxy to use for the request (as http&https)         | None                   |
| method                           | str  | HTTP method to use for the request                   | GET                    |

## Directory listing using profile

You can use a [AL submission profile](https://cybercentrecanada.github.io/assemblyline4_docs/odm/models/config/#submissionprofile) to pre-configure service to download files from directory listing. For example:

```yaml
submission:
  profiles:
    - name: "dir_listings"
      description: "Simple Downloader configured to handle directory listings, 3 levels deep"
      display_name: "Download directory listings"
      params:
        services:
          selected: ["Filtering", "Antivirus", "Static Analysis", "Extract", "Networking", "Simple-Downloader"]
        service_spec:
          Simple-Downloader:
            extract_dir_listing_as_urls: true
            extract_directories_from_listing: true
            extraction_depth: 3
```

## AL URI file
The request can also be controlled by submitting an AssemblyLine URI file. Example with the supported schema:

```yaml
# Assemblyline URI file
uri: http://xxx
method: xxx
headers:
    Header1: Value1
    Header2: Value2
```
