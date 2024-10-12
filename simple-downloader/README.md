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
