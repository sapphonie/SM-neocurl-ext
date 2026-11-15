# Compression

`Compression` (`curl_compression.inc`, included by `cURL.inc`) compresses and decompresses files and data with gzip,
zlib, raw deflate, brotli and zstd, in the background. The libraries are the ones curl uses for its content
encodings, linked into the extension.

## Formats

| `CompressFormat` | What it is | Levels (default) |
|---|---|---|
| `CompressFormat_Gzip` | gzip (`.gz`), as the gzip tool and HTTP `Content-Encoding: gzip` use it | 1-9 (6) |
| `CompressFormat_Zlib` | a zlib stream (RFC 1950), HTTP's `deflate` | 1-9 (6) |
| `CompressFormat_Deflate` | raw deflate (RFC 1951), without header | 1-9 (6) |
| `CompressFormat_Brotli` | brotli (`.br`) | 0-11 (6) |
| `CompressFormat_Zstd` | zstd (`.zst`), with a content checksum as the zstd tool writes it | 1-22 (3) |
| `CompressFormat_Auto` | decompression only: gzip, zlib or zstd, told by the first bytes | |

A level of -1 means the format's default. brotli and raw deflate have no signature, so `CompressFormat_Auto` cannot
tell them and fails with `CompressError_UnknownFormat`.

Decompression reads every member of a gzip file and every frame of a zstd file, as the gzip and zstd tools do. Bytes
after a zlib, deflate or brotli stream are `CompressError_Data`.

## How jobs run

Every native checks its arguments, copies what it needs (a string or buffer input is copied at once, so the plugin
may change or close it right after), queues a job and returns. Two threads of the extension run the jobs of all
plugins; each job's callback runs on a later server frame. With two threads, a short job is not stuck behind a long
one, and callbacks may arrive in another order than the jobs were queued.

The callback of a plugin that unloaded is not called. When the extension unloads, the running jobs are stopped and
the queued ones dropped.

## Files

```sourcepawn
Compression.CompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
                         CompressFileCallback callback, any data = 0, int level = -1,
                         bool overwrite = false, bool createPath = true);
Compression.DecompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
                           CompressFileCallback callback, any data = 0, int maxSize = 0,
                           bool overwrite = false, bool createPath = true);

typedef CompressFileCallback = function void (CompressError error, const char[] inFile, const char[] outFile,
                                              any data);
```

- Paths are relative to the game directory (`tf/` for Team Fortress 2), as for SourceMod's file functions. They must
  not leave it: absolute paths, `file://`, and empty, `.` or `..` parts are refused with a native error, on Windows
  also a `:`. `inFile` and `outFile` must differ.
- The output is written to `<outFile>.tmp` and renamed onto `outFile` once it is complete. A failed job deletes the
  temp file and leaves an existing `outFile` as it was.
- Without `overwrite`, an existing `outFile` fails the job with `CompressError_OutputExists`, also when it appears
  while the job runs.
- With `createPath`, missing directories of `outFile` are created.
- `maxSize` limits the decompressed size in bytes (0: no limit); a larger output fails with `CompressError_TooLarge`,
  so a small malicious file cannot fill the disk.

The callback gets the paths as the plugin passed them.

## Data

```sourcepawn
Compression.CompressString(CompressFormat format, const char[] input, int length,
                           CompressBufferCallback callback, any data = 0, int level = -1);
Compression.DecompressString(CompressFormat format, const char[] input, int length,
                             CompressBufferCallback callback, any data = 0, int maxSize = 16777216);
Compression.CompressBuffer(CompressFormat format, CurlBuffer buffer, CompressBufferCallback callback,
                           any data = 0, int level = -1);
Compression.DecompressBuffer(CompressFormat format, CurlBuffer buffer, CompressBufferCallback callback,
                             any data = 0, int maxSize = 16777216);

typedef CompressBufferCallback = function void (CompressError error, CurlBuffer output, any data);
```

- `length` is the number of bytes of `input`, or -1 for up to its NUL.
- The result is a [CurlBuffer](buffer.md) that lives as long as the callback, or null on error.
- `maxSize` limits the decompressed size (default 16 MB); 0 means `CurlBufferMaxBytes`, which no result may exceed.
  Compressed results are limited by `CurlBufferMaxBytes` too.

## Errors

| `CompressError` | Meaning |
|---|---|
| `CompressError_None` | Success. |
| `CompressError_OpenInput` | The input file cannot be opened. |
| `CompressError_OpenOutput` | The temp file next to the output cannot be created. |
| `CompressError_OutputExists` | The output exists and `overwrite` is false. |
| `CompressError_CreatePath` | A directory of the output cannot be created. |
| `CompressError_Read` | Reading the input failed. |
| `CompressError_Write` | Writing the output failed, e.g. the disk is full. |
| `CompressError_Data` | The input is not valid data of the format. |
| `CompressError_UnexpectedEOF` | The input ends before the compressed data does. |
| `CompressError_Memory` | Out of memory. |
| `CompressError_TooLarge` | The output would exceed `maxSize` or `CurlBufferMaxBytes`. |
| `CompressError_Rename` | The finished temp file cannot be renamed onto the output. |
| `CompressError_UnknownFormat` | `CompressFormat_Auto` found no gzip, zlib or zstd signature. |

`Compression.ErrorString(error, buffer, maxlength)` writes the name, e.g. `CompressError_Data`.

Invalid arguments (a format, level, `maxSize`, path, buffer or callback) are native errors that stop the calling
function; no job is queued then.

## Examples

Compress a demo for a fast download server and delete it when that worked:

```sourcepawn
Compression.CompressFile(CompressFormat_Gzip, "demos/match.dem", "demos/match.dem.gz", OnCompressed);

public void OnCompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		LogError("Cannot compress %s: %s", inFile, reason);
		return;
	}
	DeleteFile(inFile);
}
```

Decompress a gzip or zstd response body received into a CurlBuffer:

```sourcepawn
Compression.DecompressBuffer(CompressFormat_Auto, body, OnBody);

public void OnBody(CompressError error, CurlBuffer output, any data)
{
	if (error == CompressError_None)
		PrintToServer("%d bytes", output.Length);
}
```
