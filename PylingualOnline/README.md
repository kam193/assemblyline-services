# PylingualOnline

This service decompiles PYC files using the online service
[PyLingual.io](https://www.pylingual.io/). The API flow follows the example from
https://github.com/syssec-utd/pylingual/issues/2.

The service uploads the submitted resource/pyc file, polls PyLingual until the
result is ready, and adds the recovered source code as an extracted .py file.

Note: PyLingual.io may retain submitted code for further analysis. The service
therefore enforces a classification ceiling before uploading the file. By
default, it only proceeds with TLP:C submissions.

Configuration:

- max_classification: highest classification allowed for upload
- poll_interval: delay between progress checks
- max_request_timeout: upper bound for the upload and polling loop
