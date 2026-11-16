#if defined _curl_modern_included
  #endinput
#endif
#define _curl_modern_included

#include <cURL>

/**
 * Methodmaps over the libcurl natives of cURL.inc:
 *
 * - CurlEasy: a curl easy handle (curl_easy_init) with its options, its
 *   transfer, its result and the send & receive natives.
 * - CurlSlist: a string list (curl_slist), for CURLOPT_HTTPHEADER and the
 *   other list options.
 * - CurlForm: a multipart/formdata HTTP POST (curl_httppost).
 * - CurlFile: a file to write a transfer to or read it from (curl_OpenFile).
 *
 * Every method calls the native it names and nothing else, except the
 * shortcuts of CurlEasy, which set one option or read one info each. The
 * natives stay as they are: both may be mixed on the same handle.
 *
 * See docs/modern.md.
 */

methodmap CurlSlist < Handle
{
	/**
	 * Creates an empty string list; see curl_slist.
	 *
	 * @return              The list, null on failure. Close it with delete
	 *                      once no transfer uses it anymore.
	 */
	public CurlSlist()
	{
		return view_as<CurlSlist>(curl_slist());
	}

	/** See curl_slist_append. */
	public void Append(const char[] text)
	{
		curl_slist_append(this, text);
	}
}

methodmap CurlFile < Handle
{
	/**
	 * Opens a file for CURLOPT_WRITEDATA, CURLOPT_HEADERDATA,
	 * CURLOPT_READDATA and CURLOPT_STDERR; see curl_OpenFile.
	 *
	 * @param file          The file, relative to the game directory.
	 * @param mode          The open mode, as of fopen ("wb", "rb", ...).
	 * @return              The file, null when it cannot be opened. Close it
	 *                      with delete once its transfer is complete.
	 */
	public CurlFile(const char[] file, const char[] mode)
	{
		return view_as<CurlFile>(curl_OpenFile(file, mode));
	}
}

methodmap CurlForm < Handle
{
	/**
	 * Creates an empty multipart/formdata HTTP POST; see curl_httppost.
	 * Sections with other options than the methods here have are added with
	 * curl_formadd(form, ...).
	 *
	 * @return              The form, null on failure. Close it with delete
	 *                      once no transfer uses it anymore.
	 */
	public CurlForm()
	{
		return view_as<CurlForm>(curl_httppost());
	}

	/**
	 * Adds a section with a text; curl_formadd with CURLFORM_COPYNAME and
	 * CURLFORM_COPYCONTENTS.
	 *
	 * @param name          The section's name.
	 * @param contents      The section's contents.
	 * @return              CURL_FORMADD_OK or the error.
	 */
	public CURLFORMcode AddField(const char[] name, const char[] contents)
	{
		return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_COPYCONTENTS, contents, CURLFORM_END);
	}

	/**
	 * Adds a section that uploads a file; curl_formadd with
	 * CURLFORM_COPYNAME, CURLFORM_FILE and, when given, CURLFORM_CONTENTTYPE
	 * and CURLFORM_FILENAME.
	 *
	 * @param name          The section's name.
	 * @param path          The file, relative to the game directory.
	 * @param contentType   The file's content type; empty lets libcurl
	 *                      guess it from the file's extension.
	 * @param filename      The file name sent to the server; empty sends
	 *                      the name of the file.
	 * @return              CURL_FORMADD_OK or the error.
	 */
	public CURLFORMcode AddFile(const char[] name, const char[] path, const char[] contentType = "",
	                            const char[] filename = "")
	{
		bool hasContentType = contentType[0] != '\0';
		bool hasFilename = filename[0] != '\0';
		if (hasContentType && hasFilename) {
			return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_FILE, path, CURLFORM_CONTENTTYPE, contentType,
			                    CURLFORM_FILENAME, filename, CURLFORM_END);
		}
		if (hasContentType) {
			return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_FILE, path, CURLFORM_CONTENTTYPE, contentType,
			                    CURLFORM_END);
		}
		if (hasFilename) {
			return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_FILE, path, CURLFORM_FILENAME, filename,
			                    CURLFORM_END);
		}
		return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_FILE, path, CURLFORM_END);
	}

	/**
	 * Adds a section whose contents are read from a file, sent as a text
	 * and not as an upload; curl_formadd with CURLFORM_COPYNAME and
	 * CURLFORM_FILECONTENT.
	 *
	 * @param name          The section's name.
	 * @param path          The file, relative to the game directory.
	 * @return              CURL_FORMADD_OK or the error.
	 */
	public CURLFORMcode AddFileContent(const char[] name, const char[] path)
	{
		return curl_formadd(this, CURLFORM_COPYNAME, name, CURLFORM_FILECONTENT, path, CURLFORM_END);
	}
}

methodmap CurlEasy < Handle
{
	/**
	 * Creates a curl easy handle; see curl_easy_init. One handle is one
	 * transfer: its options reach libcurl once, when the transfer starts.
	 *
	 * @return              The handle, null on failure. Close it with delete
	 *                      once its transfer is complete.
	 */
	public CurlEasy()
	{
		return view_as<CurlEasy>(curl_easy_init());
	}

	/* --- libcurl itself --- */

	/** See curl_easy_strerror. */
	public static void StrError(CURLcode code, char[] buffer, int maxlen)
	{
		curl_easy_strerror(code, buffer, maxlen);
	}

	/** See curl_version. */
	public static void Version(char[] buffer, int maxlen)
	{
		curl_version(buffer, maxlen);
	}

	/** See curl_protocols. */
	public static void Protocols(char[] buffer, int maxlen)
	{
		curl_protocols(buffer, maxlen);
	}

	/** See curl_features. */
	public static int Features()
	{
		return curl_features();
	}

	/* --- options --- */

	/** See curl_easy_setopt_string. */
	public bool SetOptString(CURLoption opt, const char[] value)
	{
		return curl_easy_setopt_string(this, opt, value);
	}

	/** See curl_easy_setopt_int. */
	public bool SetOptInt(CURLoption opt, int value)
	{
		return curl_easy_setopt_int(this, opt, value);
	}

	/** See curl_easy_setopt_int_array. */
	public bool SetOptIntArray(int[][] array, int size)
	{
		return curl_easy_setopt_int_array(this, array, size);
	}

	/**
	 * See curl_easy_setopt_int64.
	 *
	 * @param value         The number as decimal text, e.g. "5000000000".
	 */
	public bool SetOptInt64(CURLoption opt, const char[] value)
	{
		return curl_easy_setopt_int64(this, opt, value);
	}

	/** See curl_easy_setopt_handle. */
	public bool SetOptHandle(CURLoption opt, Handle other)
	{
		return curl_easy_setopt_handle(this, opt, other);
	}

	/** See curl_easy_setopt_function. */
	public bool SetOptFunction(CURLoption opt, CURL_Function_CB callback, any value = 0)
	{
		return curl_easy_setopt_function(this, opt, callback, value);
	}

	/**
	 * Hands the options to libcurl; see curl_load_opt. Needed before
	 * Perform(), not before PerformThread(), which does it by itself. It
	 * works once per handle.
	 *
	 * @return              CURLE_OK, or the error of the first option
	 *                      libcurl refused.
	 */
	public CURLcode LoadOpt()
	{
		return curl_load_opt(this);
	}

	/* --- option shortcuts --- */

	/** Sets CURLOPT_URL. */
	public bool SetUrl(const char[] url)
	{
		return curl_easy_setopt_string(this, CURLOPT_URL, url);
	}

	/** Sets CURLOPT_HTTPHEADER: the request's own header lines. */
	public bool SetHeaders(CurlSlist headers)
	{
		return curl_easy_setopt_handle(this, CURLOPT_HTTPHEADER, headers);
	}

	/** Sets CURLOPT_USERAGENT. */
	public bool SetUserAgent(const char[] userAgent)
	{
		return curl_easy_setopt_string(this, CURLOPT_USERAGENT, userAgent);
	}

	/** Sets CURLOPT_TIMEOUT: the seconds the whole transfer may take, 0 for no limit. */
	public bool SetTimeout(int seconds)
	{
		return curl_easy_setopt_int(this, CURLOPT_TIMEOUT, seconds);
	}

	/** Sets CURLOPT_FOLLOWLOCATION: whether redirects are followed. */
	public bool SetFollowLocation(bool follow)
	{
		return curl_easy_setopt_int(this, CURLOPT_FOLLOWLOCATION, follow ? 1 : 0);
	}

	/** Sets CURLOPT_POSTFIELDS: the body of an HTTP POST, up to its NUL. */
	public bool SetPostFields(const char[] fields)
	{
		return curl_easy_setopt_string(this, CURLOPT_POSTFIELDS, fields);
	}

	/** Sets CURLOPT_HTTPPOST: a multipart/formdata HTTP POST. */
	public bool SetForm(CurlForm form)
	{
		return curl_easy_setopt_handle(this, CURLOPT_HTTPPOST, form);
	}

	/** Sets CURLOPT_WRITEDATA: the file the received body is written to. */
	public bool SetWriteFile(CurlFile file)
	{
		return curl_easy_setopt_handle(this, CURLOPT_WRITEDATA, file);
	}

	/** Sets CURLOPT_READDATA: the file an upload is read from. */
	public bool SetReadFile(CurlFile file)
	{
		return curl_easy_setopt_handle(this, CURLOPT_READDATA, file);
	}

	/** Sets CURLOPT_HEADERDATA: the file the received headers are written to. */
	public bool SetHeaderFile(CurlFile file)
	{
		return curl_easy_setopt_handle(this, CURLOPT_HEADERDATA, file);
	}

	/* --- transfer --- */

	/**
	 * Runs the transfer and returns when it is complete; see
	 * curl_easy_perform. The server stands still that long. Call LoadOpt()
	 * first: without it libcurl does not know the options.
	 */
	public CURLcode Perform()
	{
		return curl_easy_perform(this);
	}

	/**
	 * Runs the transfer on a thread and returns at once; see
	 * curl_easy_perform_thread. The callback is called in a later game
	 * frame when the transfer is complete, unless the handle was closed
	 * before, which ends the transfer.
	 */
	public void PerformThread(CURL_OnComplete callback, any value = 0)
	{
		curl_easy_perform_thread(this, callback, value);
	}

	/* --- result --- */

	/** See curl_easy_getinfo_string. */
	public CURLcode GetInfoString(CURLINFO info, char[] buffer, int maxlen)
	{
		return curl_easy_getinfo_string(this, info, buffer, maxlen);
	}

	/** See curl_easy_getinfo_int. */
	public CURLcode GetInfoInt(CURLINFO info, any &value)
	{
		return curl_easy_getinfo_int(this, info, value);
	}

	/** See curl_get_error_buffer. */
	public void GetErrorBuffer(char[] buffer, int maxlen)
	{
		curl_get_error_buffer(this, buffer, maxlen);
	}

	/**
	 * The text of a failed transfer for a log: the handle's error buffer,
	 * which names what failed (curl_get_error_buffer), or libcurl's general
	 * message for the code (curl_easy_strerror) while the buffer is empty.
	 *
	 * @param code          The code the transfer ended with.
	 * @param buffer        Destination string buffer.
	 * @param maxlen        Its length, with the NUL.
	 */
	public void GetError(CURLcode code, char[] buffer, int maxlen)
	{
		curl_get_error_buffer(this, buffer, maxlen);
		if (buffer[0] != '\0') {
			return;
		}
		curl_easy_strerror(code, buffer, maxlen);
	}

	/**
	 * CURLINFO_RESPONSE_CODE: the status of the last response (200, 404,
	 * ...), 0 when there was none.
	 */
	property int ResponseCode
	{
		public get()
		{
			int code = 0;
			curl_easy_getinfo_int(this, CURLINFO_RESPONSE_CODE, code);
			return code;
		}
	}

	/** CURLINFO_TOTAL_TIME: the seconds the last transfer took. */
	property float TotalTime
	{
		public get()
		{
			float seconds = 0.0;
			curl_easy_getinfo_int(this, CURLINFO_TOTAL_TIME, seconds);
			return seconds;
		}
	}

	/** Gets CURLINFO_EFFECTIVE_URL: the URL last used, after redirects. */
	public CURLcode GetEffectiveUrl(char[] buffer, int maxlen)
	{
		return curl_easy_getinfo_string(this, CURLINFO_EFFECTIVE_URL, buffer, maxlen);
	}

	/**
	 * Gets CURLINFO_CONTENT_TYPE: the Content-Type of the response, empty
	 * when it had none.
	 */
	public CURLcode GetContentType(char[] buffer, int maxlen)
	{
		return curl_easy_getinfo_string(this, CURLINFO_CONTENT_TYPE, buffer, maxlen);
	}

	/* --- URL encoding --- */

	/** See curl_easy_escape. */
	public bool Escape(const char[] text, char[] buffer, int maxlen)
	{
		return curl_easy_escape(this, text, buffer, maxlen);
	}

	/** See curl_easy_unescape. */
	public int Unescape(const char[] text, char[] buffer, int maxlen)
	{
		return curl_easy_unescape(this, text, buffer, maxlen);
	}

	/* --- send & receive --- */

	/** See curl_easy_send_recv. */
	public void SendRecv(CURL_OnSend onSend, CURL_OnReceive onReceive, CURL_OnComplete onComplete, SendRecv_Act act,
	                     int sendTimeout, int recvTimeout, int recvBufferSize = 1024, any value = 0)
	{
		curl_easy_send_recv(this, onSend, onReceive, onComplete, act, sendTimeout, recvTimeout, recvBufferSize, value);
	}

	/** See curl_send_recv_Signal. */
	public bool Signal(SendRecv_Act act)
	{
		return curl_send_recv_Signal(this, act);
	}

	/** See curl_send_recv_IsWaiting. */
	property bool IsWaiting
	{
		public get() { return curl_send_recv_IsWaiting(this); }
	}

	/** See curl_set_send_buffer. */
	public void SetSendBuffer(const char[] data, int size = -1)
	{
		curl_set_send_buffer(this, data, size);
	}

	/** See curl_set_receive_size. */
	public void SetReceiveSize(int size)
	{
		curl_set_receive_size(this, size);
	}

	/** See curl_set_send_timeout. */
	public void SetSendTimeout(int timeout)
	{
		curl_set_send_timeout(this, timeout);
	}

	/** See curl_set_recv_timeout. */
	public void SetRecvTimeout(int timeout)
	{
		curl_set_recv_timeout(this, timeout);
	}
}
