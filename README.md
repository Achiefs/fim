# FIM
[![Join us on Slack](https://img.shields.io/badge/Chat-Join%20us%20on%20Slack-blue)](https://join.slack.com/t/filemonitor/shared_invite/zt-1au9t0hf4-yOsW6D3pGPqzzYsAJt9Dvg)
[![GitHub](https://img.shields.io/github/license/Achiefs/fim)](https://github.com/Achiefs/fim/blob/main/LICENSE)
[![Coverage Status](https://coveralls.io/repos/github/Achiefs/fim/badge.svg)](https://coveralls.io/github/Achiefs/fim)
[![Docs](https://img.shields.io/badge/Web-Docs-brightgreen)](https://documentation.achiefs.com/)

FIM is a File Integrity Monitoring tool that tracks any event over your files. It is capable of keeping historical data of your files. It checks the filesystem changes in the background.

FIM is the fastest alternative to other software like Ossec, which performs file integrity monitoring. It could integrate with other security tools. The produced data can be ingested and analyzed with tools like ElasticSearch/OpenSearch. It has developed with Rust, a popular programming language.

## Get started
Take a look at our [Getting Started](https://documentation.achiefs.com/#how-to-install-fim) page to set up FIM.

### Configuration
To customize your installation take a look at our [Configure File Integrity Monitor](https://documentation.achiefs.com/docs/configuration-file.html#configure-file-integrity-monitor) page.

## Contribute
### Feedback
Feel free to open an issue in this repository or send your feedback to our developers through support@achiefs.com
We will be glad to hear from you and your thoughts about the product.

### How to compile
We suggest reviewing the [Development](https://documentation.achiefs.com/docs/development.html#development) page where the required setup is described.

## Features
- File watcher. FIM will emit events on any produced action over your files. It will enhance your environment to the next level of security.
- Real-time alerting. FIM works in real-time. Any change in your files will trigger at the moment.
- Fast and reliable. With rust language at the heart of FIM code. It allows us to produce faster, safer and more reliable code.
- Ingester integrated. FIM supports native events sent to any current indexer like OpenSearch, ElasticSearch and Wazuh indexer. Enhance your experience.
- Identification of changes in content, attributes, ownership or permissions.
- Extended detected event data, using Audit Linux daemon. Retrieve who produces an event and which command produces it.
- Historical logs storage of detected events.
- File integrity checking. Automated file integrity hash production. FIM will analyze each file change.
- Compatible with Linux, macOS and Windows.
- Open Source software. Our software is developed as a completely free open-source model. It includes a TDD methodology to produce better software.

Testing change
