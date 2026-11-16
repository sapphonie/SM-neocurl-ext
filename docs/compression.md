# Compression

`Compression` compresses and decompresses files and data in memory with gzip, zlib, raw deflate, brotli and zstd. The
work is done by threads of the extension, so a plugin can compress a 200 MB demo without the server missing a tick.

It is part of `curl_compression.inc`, which `#include <cURL>` includes. bzip2 (`.bz2`), the format of Source's fast
download servers, is not among the formats.

Contents:

- [A first example](#a-first-example)
- [How jobs run](#how-jobs-run)
- [Formats and levels](#formats-and-levels)
- [Files](#files)
- [Data in memory](#data-in-memory)
- [Errors](#errors)
- [Complete example: keep demos compressed](#complete-example-keep-demos-compressed)
- [Reference](#reference)
- [Common mistakes](#common-mistakes)

## A first example

Compress a demo with zstd, and delete the original when that worked. From
[`compression_demos.sp`](../pawn/scripting/examples/compression_demos.sp):

```sourcepawn
Compression.CompressFile(CompressFormat_Zstd, name, compressed, OnDemoCompressed);
```

```sourcepawn
public void OnDemoCompressed(CompressError error, const char[] inFile, const char[] outFile, any data)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		LogError("Cannot compress %s: %s", inFile, reason);
		return;
	}

	LogMessage("Compressed %s: %d to %d bytes", inFile, FileSize(inFile), FileSize(outFile));
	// Only now, with the compressed file complete, the original goes.
	DeleteFile(inFile);
}
```

`Compression` is not an object: there is nothing to create or delete. Its methods are called on the name itself.

## How jobs run

Every method of `Compression` except `ErrorString` starts a **job**:

1. The method checks its arguments. A wrong argument throws an error at once and no job is started (see
   [Errors](#errors)).
2. It puts the job into a queue and returns immediately. Data given as a string or `CurlBuffer` is copied at that
   moment, so the plugin may change or delete it right after the call.
3. Two threads of the extension work through the queue, for all plugins together.
4. When a job is finished, its callback is called on the server's main thread, in a later game frame, with the
   result.

Because two jobs run at the same time, a short job can finish before a long one that was started earlier. Callbacks
may therefore arrive in a different order than the jobs were started. Every callback gets the `data` value that was
passed when its job was started; use it to tell the jobs apart.

If the plugin is unloaded while its jobs are queued or running, the jobs are still carried out (a file job still
writes its output file), but their callbacks are not called.

## Formats and levels

The format is a value of the enum `CompressFormat`:

| `CompressFormat` | What it is | Usual file extension | Levels | Default level |
|---|---|---|---|---|
| `CompressFormat_Gzip` | gzip, as the `gzip` tool writes it and web servers use it | `.gz` | 1 to 9 | 6 |
| `CompressFormat_Zlib` | a zlib stream (RFC 1950); HTTP calls it `deflate` | none | 1 to 9 | 6 |
| `CompressFormat_Deflate` | raw deflate (RFC 1951): a zlib stream without header and checksum | none | 1 to 9 | 6 |
| `CompressFormat_Brotli` | brotli | `.br` | 0 to 11 | 6 |
| `CompressFormat_Zstd` | zstd, with a checksum of the content | `.zst` | 1 to 22 | 3 |
| `CompressFormat_Auto` | only for decompressing: detect the format | | | |

The **level** trades time for size: a higher level compresses better and takes longer. -1 selects the default level
of the format, which is a good choice unless there is a reason for another. A level outside the format's range
throws an error. Decompressing needs no level; it works for data of every level.

Which format to pick:

- **zstd** for files the server keeps for itself. It usually compresses faster than the others for the same size.
- **gzip** when something else has to read the result and it is not known what it supports.
- **brotli** for text that is served to web browsers.
- **zlib** and **deflate** only when a protocol or file format asks for exactly them.

### Detecting the format

`CompressFormat_Auto` looks at the first bytes of the input and picks gzip, zlib or zstd. Data in these formats begins
with a few fixed bytes, a signature, by which it can be recognised. Brotli and raw deflate have none and cannot be
detected: for those, name the format. When the input begins with none of the three signatures, the job fails with
`CompressError_UnknownFormat`.

A gzip file may consist of several gzip files written one after another, and so may a zstd file; both are
decompressed completely, as the `gzip` and `zstd` tools do. For zlib, deflate and brotli, bytes after the end of the
compressed data are an error (`CompressError_Data`).

## Files

```sourcepawn
void Compression.CompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
                              CompressFileCallback callback, any data = 0, int level = -1,
                              bool overwrite = false, bool createPath = true)

void Compression.DecompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
                                CompressFileCallback callback, any data = 0, int maxSize = 0,
                                bool overwrite = false, bool createPath = true)
```

The callback:

```sourcepawn
public void OnFileDone(CompressError error, const char[] inFile, const char[] outFile, any data)
```

`error` is `CompressError_None` when the job worked. `inFile` and `outFile` are the paths exactly as the plugin
passed them, and `data` is the value given as `data` when the job was started.

### Paths

- Paths are relative to the game directory (`tf/` for Team Fortress 2), like the paths of SourceMod's file functions:
  `"demos/match.dem"`.
- A path must stay inside the game directory. An absolute path, a path that starts with `file://`, an empty path and
  a path with an empty, `.` or `..` part (`"a//b"`, `"demos/"`, `"../x"`) throw an error. On Windows so does a path
  that contains `:`.
- `inFile` and `outFile` must be different paths, or the method throws an error.

### How the output file is written

The job writes to a temporary file next to the output, named `<outFile>.tmp`, and renames it to `outFile` when it is
complete. So `outFile` is never a half-written file: it either does not exist (or is the old file), or it is whole.
A job that fails deletes its temporary file and leaves an existing `outFile` untouched.

- **`overwrite`**: when `outFile` exists already and `overwrite` is `false`, the job fails with
  `CompressError_OutputExists`. With `true` the existing file is replaced. The check is made when the job runs,
  not when it is started, and again when the finished file is renamed.
- **`createPath`**: with `true`, directories of `outFile` that do not exist are created. With `false`, a missing
  directory makes the job fail with `CompressError_OpenOutput`. The directories are created before the input is
  opened, so they remain when the job then fails because the input does not exist.

Two things to avoid:

- Do not run two jobs with the same `outFile` at the same time: they would write to the same temporary file.
- Do not keep a file of your own under the name `<outFile>.tmp`. A job overwrites it, whatever `overwrite` says.

### Limiting the size of decompressed files

A few kilobytes of compressed data can unpack to gigabytes. `maxSize` protects the disk: when the decompressed data
would be larger than `maxSize` bytes, the job fails with `CompressError_TooLarge`. 0, the default, means no limit. The
largest limit that can be given is 2147483647 bytes (2 GB minus one byte). Set a limit whenever the compressed file
comes from somewhere else, such as a download or an upload:

```sourcepawn
// CompressFormat_Auto tells gzip, zlib and zstd apart by the first
// bytes of the file. The size limit protects the disk from a small
// file that unpacks to something huge.
int userId = client == 0 ? 0 : GetClientUserId(client);
Compression.DecompressFile(CompressFormat_Auto, compressed, target, OnDemoDecompressed, userId, MAX_DEMO_SIZE);
```

```sourcepawn
public void OnDemoDecompressed(CompressError error, const char[] inFile, const char[] outFile, int userId)
{
	// The player who asked may have left meanwhile; 0 is the console.
	int client = userId == 0 ? 0 : GetClientOfUserId(userId);
	if (userId != 0 && client == 0) {
		return;
	}

	if (error == CompressError_OutputExists) {
		ReplyToCommand(client, "%s exists already.", outFile);
	} else if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		ReplyToCommand(client, "Cannot unpack %s: %s", inFile, reason);
	} else {
		ReplyToCommand(client, "Unpacked %s: %d bytes", outFile, FileSize(outFile));
	}
}
```

## Data in memory

The same for data that is not in a file. The input is a string or a [`CurlBuffer`](buffer.md); the output is always a
`CurlBuffer`, because it may be larger than a plugin's memory.

```sourcepawn
void Compression.CompressString(CompressFormat format, const char[] input, int length,
                                CompressBufferCallback callback, any data = 0, int level = -1)
void Compression.DecompressString(CompressFormat format, const char[] input, int length,
                                  CompressBufferCallback callback, any data = 0, int maxSize = 16777216)
void Compression.CompressBuffer(CompressFormat format, CurlBuffer buffer,
                                CompressBufferCallback callback, any data = 0, int level = -1)
void Compression.DecompressBuffer(CompressFormat format, CurlBuffer buffer,
                                  CompressBufferCallback callback, any data = 0, int maxSize = 16777216)
```

The callback:

```sourcepawn
public void OnDataDone(CompressError error, CurlBuffer output, any data)
```

- `length` is the number of bytes of `input`. -1 means: up to the NUL, for text. Compressed data is binary and
  contains NUL bytes, so `DecompressString` needs the real length.
- `output` is the result. It is `null` when the job failed. It exists only while the callback runs; see
  [Buffers the extension passes to a callback](buffer.md#buffers-the-extension-passes-to-a-callback).
- `maxSize` limits the decompressed size, 16 MB (16777216 bytes) by default. A larger result fails the job with
  `CompressError_TooLarge`. 0 means "as large as a buffer may be", which is
  [`CurlBufferMaxBytes`](buffer.md#the-size-limit); a higher value is lowered to that. Compressed results are
  limited by `CurlBufferMaxBytes` as well.

A text is compressed with gzip and unpacked again:

```sourcepawn
public Action Command_CompressText(int client, int args)
{
	char text[256];
	GetCmdArgString(text, sizeof(text));

	// -1: the input is the text up to its NUL. Level 9 is gzip's best.
	Compression.CompressString(CompressFormat_Gzip, text, -1, OnTextCompressed, strlen(text), 9);
	return Plugin_Handled;
}
```

```sourcepawn
public void OnTextCompressed(CompressError error, CurlBuffer output, int originalLength)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot compress: %s", reason);
		return;
	}

	PrintToServer("gzip: %d bytes became %d", originalLength, output.Length);

	// The buffer lives only as long as this callback, but a job copies
	// its input when it is queued: passing the buffer on is safe.
	Compression.DecompressBuffer(CompressFormat_Gzip, output, OnTextDecompressed, 0, 4096);
}
```

```sourcepawn
public void OnTextDecompressed(CompressError error, CurlBuffer output, any data)
{
	if (error != CompressError_None) {
		char reason[32];
		Compression.ErrorString(error, reason, sizeof(reason));
		PrintToServer("Cannot decompress: %s", reason);
		return;
	}

	char text[256];
	output.GetString(0, text, sizeof(text));
	PrintToServer("and back: %s", text);
}
```

`sm_compress_text rocket rocket rocket rocket rocket rocket sticky sticky sticky` prints:

```
gzip: 62 bytes became 37
and back: rocket rocket rocket rocket rocket rocket sticky sticky sticky
```

Short inputs can grow, because every format adds a header: the nine bytes of `aaaa bbbb` become 27 bytes of gzip.

## Errors

A job that fails reports one of these values of `CompressError` to its callback:

| `CompressError` | Meaning |
|---|---|
| `CompressError_None` | The job worked. |
| `CompressError_OpenInput` | The input file cannot be opened. Usually it does not exist. |
| `CompressError_OpenOutput` | The temporary file next to the output cannot be created: the directory is missing (with `createPath` false) or not writable. |
| `CompressError_OutputExists` | The output file exists and `overwrite` is `false`. |
| `CompressError_CreatePath` | A directory of the output cannot be created. |
| `CompressError_Read` | Reading the input file failed. |
| `CompressError_Write` | Writing the output failed. Usually the disk is full. |
| `CompressError_Data` | The input is not valid data of the format, or it is damaged. |
| `CompressError_UnexpectedEOF` | The input ends before the compressed data is complete: a cut-off file, or empty input. (With `CompressFormat_Auto`, empty input is `CompressError_UnknownFormat`.) |
| `CompressError_Memory` | Out of memory. |
| `CompressError_TooLarge` | The output would be larger than `maxSize` or than `CurlBufferMaxBytes`. |
| `CompressError_Rename` | The finished temporary file cannot be renamed to the output file. |
| `CompressError_UnknownFormat` | `CompressFormat_Auto` found no gzip, zlib or zstd signature. |

For a log message, `ErrorString` turns a value into its name:

```sourcepawn
int Compression.ErrorString(CompressError error, char[] buffer, int maxlength)
```

It writes the name, for example `CompressError_Data`, and returns its length. A buffer of 32 bytes holds every name.
A value that is not one of the enum's throws an error.

```sourcepawn
if (error != CompressError_None) {
	char reason[32];
	Compression.ErrorString(error, reason, sizeof(reason));
	LogError("Cannot compress %s: %s", inFile, reason);
	return;
}
```

Errors of the second kind are mistakes in the call, not in the data. They throw an error, which is written to
SourceMod's error log and stops the calling function; no job is started and no callback is called:

- a format or level that does not exist, or `CompressFormat_Auto` for compressing,
- a negative `maxSize`, or a `length` below -1,
- a path that is not allowed (see [Paths](#paths)),
- an invalid `CurlBuffer`, or an invalid callback.

## Complete example: keep demos compressed

[`compression_demos.sp`](../pawn/scripting/examples/compression_demos.sp) has two commands for the demos in the game
directory.

`sm_demos_compress` goes through the directory and starts one job per demo. The jobs wait in the queue and are worked
off two at a time:

```sourcepawn
public Action Command_Compress(int client, int args)
{
	DirectoryListing directory = OpenDirectory(".");
	if (directory == null) {
		ReplyToCommand(client, "Cannot list the game directory.");
		return Plugin_Handled;
	}

	int count = 0;
	char name[PLATFORM_MAX_PATH];
	FileType type;
	while (directory.GetNext(name, sizeof(name), type)) {
		int length = strlen(name);
		if (type != FileType_File || length < 5 || !StrEqual(name[length - 4], ".dem")) {
			continue;
		}

		char compressed[PLATFORM_MAX_PATH];
		Format(compressed, sizeof(compressed), "%s.zst", name);
		// Queues the job and returns at once. Level -1 is the format's
		// default. An existing .zst file fails the job instead of being
		// replaced, because overwrite is false by default.
		Compression.CompressFile(CompressFormat_Zstd, name, compressed, OnDemoCompressed);
		count++;
	}
	delete directory;

	ReplyToCommand(client, "Compressing %d demos in the background.", count);
	return Plugin_Handled;
}
```

Each demo's callback deletes the original only after its compressed file is complete; it is the first example on
this page. The server log:

```
Compressed demo1.dem: 400007 to 73 bytes
Compressed demo2.dem: 400007 to 73 bytes
```

`sm_demos_decompress demo1.dem.zst` unpacks one again, as shown under
[Limiting the size of decompressed files](#limiting-the-size-of-decompressed-files). The callback answers the player
who gave the command, who may have left meanwhile, hence the user id as `data`.

## Reference

| Method | Native |
|---|---|
| `Compression.CompressFile` | `compression_compress_file` |
| `Compression.DecompressFile` | `compression_decompress_file` |
| `Compression.CompressString` | `compression_compress_string` |
| `Compression.DecompressString` | `compression_decompress_string` |
| `Compression.CompressBuffer` | `compression_compress_buffer` |
| `Compression.DecompressBuffer` | `compression_decompress_buffer` |
| `Compression.ErrorString` | `compression_error_string` |

The natives take the same arguments in the same order as the methods.

| Type | Definition |
|---|---|
| `CompressFileCallback` | `function void (CompressError error, const char[] inFile, const char[] outFile, any data)` |
| `CompressBufferCallback` | `function void (CompressError error, CurlBuffer output, any data)` |

`data` may be declared with the type that was passed, such as `int` or `DataPack`.

Defaults and limits at a glance:

| | Files | Data in memory |
|---|---|---|
| Level when compressing | -1: the format's default | -1: the format's default |
| `maxSize` when decompressing | 0: no limit | 16777216 (16 MB); 0: `CurlBufferMaxBytes` |
| Size of a compressed result | no limit | `CurlBufferMaxBytes` |
| `overwrite` | `false` | |
| `createPath` | `true` | |

## Common mistakes

- **Using the result right after the call.** The methods only start a job. The output file or buffer exists when the
  callback is called, not before.
- **Deleting the input too early.** Delete the original of a compressed file in the callback, after checking that
  `error` is `CompressError_None`.
- **Expecting callbacks in the order of the calls.** Two jobs run at once; a small one overtakes a big one. Use `data`
  to know which job a callback belongs to.
- **Keeping the output buffer.** The `CurlBuffer` of a callback is closed when the callback returns. Use `Clone()` to
  keep it.
- **Passing -1 as the length of compressed data.** Compressed data contains NUL bytes, so "up to the NUL" cuts it
  off. Pass its real length, or keep it in a `CurlBuffer`.
- **Decompressing foreign data without `maxSize`.** For files the default is no limit at all.
- **Using `CompressFormat_Auto` for brotli or raw deflate.** They cannot be detected. Name the format.
- **Absolute paths.** All paths are relative to the game directory and cannot leave it.
- **Expecting an existing file to be replaced.** `overwrite` is `false` by default, and the job fails with
  `CompressError_OutputExists`.
