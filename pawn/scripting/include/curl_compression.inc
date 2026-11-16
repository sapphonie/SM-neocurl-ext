#if defined _curl_compression_included
  #endinput
#endif
#define _curl_compression_included

#include <cURL>

/**
 * Compression: gzip, zlib, raw deflate, brotli and zstd compression and
 * decompression of files and data, in the background. Two threads of the
 * extension run the jobs; each job's callback runs on a later server frame,
 * so callbacks may arrive in another order than the jobs were queued.
 *
 * See docs/compression.md.
 */

enum CompressFormat
{
	CompressFormat_Gzip = 0,  /**< gzip (.gz), as the gzip tool writes it. */
	CompressFormat_Zlib,      /**< zlib stream (RFC 1950). */
	CompressFormat_Deflate,   /**< Raw deflate (RFC 1951). */
	CompressFormat_Brotli,    /**< brotli (.br). */
	CompressFormat_Zstd,      /**< zstd (.zst), with a content checksum. */
	CompressFormat_Auto,      /**< Decompression only: gzip, zlib or zstd, told by the first bytes. */
};

enum CompressError
{
	CompressError_None = 0,       /**< Success. */
	CompressError_OpenInput,      /**< The input file cannot be opened. */
	CompressError_OpenOutput,     /**< The temp file next to the output cannot be created. */
	CompressError_OutputExists,   /**< The output exists and overwrite is false. */
	CompressError_CreatePath,     /**< The output's directory cannot be created. */
	CompressError_Read,           /**< Reading the input failed. */
	CompressError_Write,          /**< Writing the output failed (e.g. disk full). */
	CompressError_Data,           /**< The input is not valid data of the format. */
	CompressError_UnexpectedEOF,  /**< The input ends before the compressed data does. */
	CompressError_Memory,         /**< Out of memory. */
	CompressError_TooLarge,       /**< The output would exceed maxSize (or CurlBufferMaxBytes). */
	CompressError_Rename,         /**< The finished temp file cannot be renamed onto the output. */
	CompressError_UnknownFormat,  /**< CompressFormat_Auto found no gzip, zlib or zstd signature. */
};

/**
 * Called when a file job ended.
 *
 * @param error         CompressError_None on success.
 * @param inFile        The input path as it was passed.
 * @param outFile       The output path as it was passed.
 * @param data          The data passed with the job.
 */
typedef CompressFileCallback = function void (CompressError error, const char[] inFile, const char[] outFile, any data);

/**
 * Called when a data job ended.
 *
 * @param error         CompressError_None on success.
 * @param output        The result, or null on error. It lives as long as
 *                      the callback; use output.Clone() to keep it.
 * @param data          The data passed with the job.
 */
typedef CompressBufferCallback = function void (CompressError error, CurlBuffer output, any data);

/**
 * Compresses a file into another, in the background.
 *
 * Paths are relative to the game directory, as for SourceMod's file
 * functions, and must not leave it: absolute paths, "file://", an empty
 * path and empty, "." or ".." parts are refused, on Windows also ":". The
 * output is written to "<outFile>.tmp" and renamed onto
 * outFile once complete; a failed job leaves no file behind and does not
 * touch an existing outFile.
 *
 * @param format        The format; not CompressFormat_Auto.
 * @param inFile        The file to compress.
 * @param outFile       The file to write.
 * @param callback      Called when the job ended.
 * @param data          Passed to the callback.
 * @param level         The compression level, or -1 for the format's
 *                      default: gzip, zlib, deflate 1-9 (default 6),
 *                      brotli 0-11 (default 6), zstd 1-22 (default 3).
 * @param overwrite     Whether an existing outFile is replaced.
 * @param createPath    Whether missing directories of outFile are created.
 * @error               Invalid format, level, path or callback, or inFile
 *                      and outFile are the same file.
 */
native void compression_compress_file(CompressFormat format, const char[] inFile, const char[] outFile,
                                      CompressFileCallback callback, any data = 0, int level = -1,
                                      bool overwrite = false, bool createPath = true);

/**
 * Decompresses a file into another, in the background. Paths and the
 * output as for compression_compress_file. Concatenated gzip members and
 * zstd frames are all decompressed.
 *
 * @param format        The format, or CompressFormat_Auto.
 * @param inFile        The file to decompress.
 * @param outFile       The file to write.
 * @param callback      Called when the job ended.
 * @param data          Passed to the callback.
 * @param maxSize       The most bytes the output may have (else
 *                      CompressError_TooLarge), 0 for no limit.
 * @param overwrite     Whether an existing outFile is replaced.
 * @param createPath    Whether missing directories of outFile are created.
 * @error               Invalid format, maxSize, path or callback, or inFile
 *                      and outFile are the same file.
 */
native void compression_decompress_file(CompressFormat format, const char[] inFile, const char[] outFile,
                                        CompressFileCallback callback, any data = 0, int maxSize = 0,
                                        bool overwrite = false, bool createPath = true);

/**
 * Compresses bytes, in the background; the input is copied at once.
 *
 * @param format        The format; not CompressFormat_Auto.
 * @param input         The bytes.
 * @param length        How many bytes of input, or -1 for up to its NUL.
 * @param callback      Called with the result.
 * @param data          Passed to the callback.
 * @param level         As for compression_compress_file.
 * @error               Invalid format, length, level or callback.
 */
native void compression_compress_string(CompressFormat format, const char[] input, int length,
                                        CompressBufferCallback callback, any data = 0, int level = -1);

/**
 * Decompresses bytes, in the background; the input is copied at once.
 *
 * @param format        The format, or CompressFormat_Auto.
 * @param input         The bytes.
 * @param length        How many bytes of input, or -1 for up to its NUL.
 * @param callback      Called with the result.
 * @param data          Passed to the callback.
 * @param maxSize       The most bytes the result may have (else
 *                      CompressError_TooLarge); 0 for CurlBufferMaxBytes.
 * @error               Invalid format, length, maxSize or callback.
 */
native void compression_decompress_string(CompressFormat format, const char[] input, int length,
                                          CompressBufferCallback callback, any data = 0,
                                          int maxSize = 16777216);

/**
 * Compresses the bytes of a buffer, in the background; they are copied at
 * once, so the buffer may change or be closed right after.
 *
 * @param format        The format; not CompressFormat_Auto.
 * @param buffer        The CurlBuffer.
 * @param callback      Called with the result.
 * @param data          Passed to the callback.
 * @param level         As for compression_compress_file.
 * @error               Invalid format, buffer, level or callback.
 */
native void compression_compress_buffer(CompressFormat format, Handle buffer, CompressBufferCallback callback,
                                        any data = 0, int level = -1);

/**
 * Decompresses the bytes of a buffer, in the background; they are copied
 * at once.
 *
 * @param format        The format, or CompressFormat_Auto.
 * @param buffer        The CurlBuffer.
 * @param callback      Called with the result.
 * @param data          Passed to the callback.
 * @param maxSize       As for compression_decompress_string.
 * @error               Invalid format, buffer, maxSize or callback.
 */
native void compression_decompress_buffer(CompressFormat format, Handle buffer, CompressBufferCallback callback,
                                          any data = 0, int maxSize = 16777216);

/**
 * Writes the name of an error, e.g. "CompressError_Data".
 *
 * @param error         The error.
 * @param buffer        The string to write into.
 * @param maxlength     The size of buffer.
 * @return              The number of bytes written.
 * @error               Invalid error.
 */
native int compression_error_string(CompressError error, char[] buffer, int maxlength);

methodmap Compression
{
	/** See compression_compress_file. */
	public static void CompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
	                                CompressFileCallback callback, any data = 0, int level = -1,
	                                bool overwrite = false, bool createPath = true)
	{
		compression_compress_file(format, inFile, outFile, callback, data, level, overwrite, createPath);
	}

	/** See compression_decompress_file. */
	public static void DecompressFile(CompressFormat format, const char[] inFile, const char[] outFile,
	                                  CompressFileCallback callback, any data = 0, int maxSize = 0,
	                                  bool overwrite = false, bool createPath = true)
	{
		compression_decompress_file(format, inFile, outFile, callback, data, maxSize, overwrite, createPath);
	}

	/** See compression_compress_string. */
	public static void CompressString(CompressFormat format, const char[] input, int length,
	                                  CompressBufferCallback callback, any data = 0, int level = -1)
	{
		compression_compress_string(format, input, length, callback, data, level);
	}

	/** See compression_decompress_string. */
	public static void DecompressString(CompressFormat format, const char[] input, int length,
	                                    CompressBufferCallback callback, any data = 0, int maxSize = 16777216)
	{
		compression_decompress_string(format, input, length, callback, data, maxSize);
	}

	/** See compression_compress_buffer. */
	public static void CompressBuffer(CompressFormat format, CurlBuffer buffer, CompressBufferCallback callback,
	                                  any data = 0, int level = -1)
	{
		compression_compress_buffer(format, buffer, callback, data, level);
	}

	/** See compression_decompress_buffer. */
	public static void DecompressBuffer(CompressFormat format, CurlBuffer buffer, CompressBufferCallback callback,
	                                    any data = 0, int maxSize = 16777216)
	{
		compression_decompress_buffer(format, buffer, callback, data, maxSize);
	}

	/** See compression_error_string. */
	public static int ErrorString(CompressError error, char[] buffer, int maxlength)
	{
		return compression_error_string(error, buffer, maxlength);
	}
}
