#if defined _curl_buffer_included
  #endinput
#endif
#define _curl_buffer_included

#include <cURL>

/**
 * CurlBuffer: a byte buffer of the cURL extension. It carries data that may
 * be larger than a plugin's own memory (received WebSocket messages,
 * compression results, digests) and may hold any bytes, NUL included.
 *
 * A buffer never grows beyond "CurlBufferMaxBytes" in SourceMod's core.cfg
 * (default 268435456, 256 MB); appending more throws an error.
 *
 * A buffer passed to a callback lives only as long as the callback; use
 * Clone() (curl_buffer_clone) to keep its bytes. It is writable while it
 * lives.
 *
 * See docs/buffer.md.
 */

/**
 * Creates an empty buffer. Close it with delete or CloseHandle().
 *
 * @return              The buffer.
 */
native Handle curl_buffer_create();

/**
 * @param buffer        The buffer.
 * @return              The number of bytes in the buffer.
 */
native int curl_buffer_length(Handle buffer);

/**
 * Removes all bytes and frees their memory.
 *
 * @param buffer        The buffer.
 */
native void curl_buffer_clear(Handle buffer);

/**
 * Appends length bytes of data; data may contain NUL bytes.
 *
 * @param buffer        The buffer.
 * @param data          The bytes.
 * @param length        How many bytes of data to append.
 * @error               Invalid buffer, negative length, or the buffer would
 *                      exceed CurlBufferMaxBytes.
 */
native void curl_buffer_append(Handle buffer, const char[] data, int length);

/**
 * Appends text up to its NUL, without the NUL.
 *
 * @param buffer        The buffer.
 * @param text          The text.
 * @error               Invalid buffer, or the buffer would exceed
 *                      CurlBufferMaxBytes.
 */
native void curl_buffer_append_string(Handle buffer, const char[] text);

/**
 * Appends the bytes of other (which may be buffer itself).
 *
 * @param buffer        The buffer.
 * @param other         The buffer whose bytes to append.
 * @error               Invalid buffers, or the buffer would exceed
 *                      CurlBufferMaxBytes.
 */
native void curl_buffer_append_buffer(Handle buffer, Handle other);

/**
 * Copies bytes from offset into output as a string: at most maxlength - 1
 * bytes, followed by a NUL. A NUL in the copied bytes ends the string early
 * for SourcePawn's string functions.
 *
 * @param buffer        The buffer.
 * @param offset        Where to start, 0 to Length.
 * @param output        The string to copy into.
 * @param maxlength     The size of output.
 * @return              The number of bytes copied, without the NUL.
 * @error               Invalid buffer, offset outside the buffer, or
 *                      maxlength below 1.
 */
native int curl_buffer_get_string(Handle buffer, int offset, char[] output, int maxlength);

/**
 * Copies at most count bytes from offset into output, without a NUL.
 *
 * @param buffer        The buffer.
 * @param offset        Where to start, 0 to Length.
 * @param output        The array to copy into; at least count bytes.
 * @param count         The most bytes to copy.
 * @return              The number of bytes copied.
 * @error               Invalid buffer, offset outside the buffer, or
 *                      negative count.
 */
native int curl_buffer_get_bytes(Handle buffer, int offset, char[] output, int count);

/**
 * @param buffer        The buffer.
 * @param index         The position of the byte, 0 to Length - 1.
 * @return              The byte, 0-255.
 * @error               Invalid buffer or index outside the buffer.
 */
native int curl_buffer_get(Handle buffer, int index);

/**
 * Finds the first occurrence of pattern at or after start.
 *
 * @param buffer        The buffer.
 * @param pattern       The bytes to find.
 * @param length        How many bytes of pattern, or -1 for up to its NUL.
 * @param start         Where to start searching, 0 to Length.
 * @return              The position of the match, or -1.
 * @error               Invalid buffer, length below -1 or start outside
 *                      the buffer.
 */
native int curl_buffer_find(Handle buffer, const char[] pattern, int length = -1, int start = 0);

/**
 * Creates a new buffer with a copy of the bytes.
 *
 * @param buffer        The buffer.
 * @return              The copy. Close it with delete or CloseHandle().
 * @error               Invalid buffer.
 */
native Handle curl_buffer_clone(Handle buffer);

methodmap CurlBuffer < Handle
{
	/**
	 * Creates an empty buffer; see curl_buffer_create.
	 */
	public CurlBuffer()
	{
		return view_as<CurlBuffer>(curl_buffer_create());
	}

	/**
	 * The number of bytes in the buffer; see curl_buffer_length.
	 */
	property int Length
	{
		public get() { return curl_buffer_length(this); }
	}

	/** See curl_buffer_clear. */
	public void Clear()
	{
		curl_buffer_clear(this);
	}

	/** See curl_buffer_append. */
	public void Append(const char[] data, int length)
	{
		curl_buffer_append(this, data, length);
	}

	/** See curl_buffer_append_string. */
	public void AppendString(const char[] text)
	{
		curl_buffer_append_string(this, text);
	}

	/** See curl_buffer_append_buffer. */
	public void AppendBuffer(CurlBuffer other)
	{
		curl_buffer_append_buffer(this, other);
	}

	/** See curl_buffer_get_string. */
	public int GetString(int offset, char[] output, int maxlength)
	{
		return curl_buffer_get_string(this, offset, output, maxlength);
	}

	/** See curl_buffer_get_bytes. */
	public int GetBytes(int offset, char[] output, int count)
	{
		return curl_buffer_get_bytes(this, offset, output, count);
	}

	/** See curl_buffer_get. */
	public int Get(int index)
	{
		return curl_buffer_get(this, index);
	}

	/** See curl_buffer_find. */
	public int Find(const char[] pattern, int length = -1, int start = 0)
	{
		return curl_buffer_find(this, pattern, length, start);
	}

	/** See curl_buffer_clone. */
	public CurlBuffer Clone()
	{
		return view_as<CurlBuffer>(curl_buffer_clone(this));
	}
}
