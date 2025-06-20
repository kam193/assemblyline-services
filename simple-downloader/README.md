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
| predefined_proxy                 | list | Select a predefined proxy to use                     | `none`                 |

In addition, you can specify following service parameters:

| Name                             | Type | Description                                          | Default                |
| -------------------------------- | ---- | ---------------------------------------------------- | ---------------------- |
| timeout                          | int  | Timeout for the request in seconds                   | 150                    |
| max_file_size                    | int  | Maximum file size to download in bytes               | 524288000 (500 MB)     |
| proxies                          | dict | Dictionary of available predefined proxies           | `{"name": "uri"}`      |

Service will abort downloading if file size is larger than the configured limit, but will still return related metadata
(headers, redirects, etc.).

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
          selected: ["Filtering", "Antivirus", "Static Analysis", "Extraction", "Networking", "Simple-Downloader"]
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

## Proxies

You can ad-hock define a proxy in the submission (using `proxy` parameter) or
predefine proxies. To do that, you have to modify the `proxies` service parameter:
this is a dictionary with keys as proxy identifiers and values as proxy URIs.
After adding new proxies, modify the available options for the `predefined_proxy`
submission parameter. Select it during the submission to use one of those proxies.

The ad-hock proxy takes precedence over predefined one, if both are specified.