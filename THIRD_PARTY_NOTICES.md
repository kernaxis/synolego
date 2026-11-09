# Third-party notices

Synolego is distributed under the MIT license in [LICENSE](LICENSE). Its CLI
includes code from Lego v4.25.1; the original copyrights of Ludovic Fernandez
and Sebastian Erhart are retained in that license.

Dependencies remain under their own licenses. Release archives contain:

- `LICENSE`: the project MIT license and incorporated Lego attributions.
- `THIRD_PARTY_LICENSES.txt`: the generated dependency inventory, exact versions,
  source links, full license texts, copyright notices and applicable NOTICE files.
- `MPL-2.0-SOURCES.tar.gz`: the complete, unmodified sources of the distributed
  MPL-2.0 modules, including their original license notices.

The generated text also includes the Go runtime and standard-library notices
from the toolchain used to build the binary. The Oracle OCI components offer
UPL-1.0 OR Apache-2.0; this distribution selects their Apache-2.0 option.

MPL-covered files remain under MPL-2.0. Their corresponding sources are supplied
in the release archive; separate Synolego files remain MIT-licensed. A service or
binary consuming these files does not remove their original license obligations.

## Maintaining the notices

The detailed catalogue and dependency sources are **not vendored in this repo**.
`scripts/package_licenses.py` generates them in the build directory during
`make package`, using go-licenses v2.0.1 and the actual compilation graph.
It rejects unrecognized licenses and includes reviewed, version-specific
handling for short-form or source-header declarations that the classifier
cannot identify automatically. Changes to those exceptions require review.

Install the packaging tool with:

```sh
go install github.com/google/go-licenses/v2@v2.0.1
```

Packaging also requires Python 3. Generated redistribution materials belong
in `dist/` (ignored by Git), not in the source tree. Keep them with distributed
binaries. Do not strip notices when repackaging a release.
