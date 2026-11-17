/**
 * Example: upload a SourceTV demo to demos.tf.
 *
 * Shows a multipart/formdata POST with CurlForm (text fields and a file),
 * reading a short answer into the plugin's memory with a write callback, and
 * a progress callback that reports how much of the upload is sent.
 *
 * demos.tf answers every upload with status 200 and one line of text:
 * "STV available at: https://demos.tf/<number>" on success, otherwise the
 * reason ("Invalid key", "No demo uploaded", ...).
 *
 *   sm_demostf_apikey "<your API key from demos.tf>"
 *   sm_uploaddemo match.dem
 *
 * The file name is relative to the game directory.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: demos.tf upload",
	author = "davenonymous",
	description = "Uploads SourceTV demos to demos.tf",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_UploadUrl;
ConVar g_ApiKey;

// One upload at a time: the answer of the running upload is collected here.
CurlForm g_Form;
char g_Answer[256];

public void OnPluginStart()
{
	g_UploadUrl = CreateConVar("sm_demostf_url", "https://demos.tf/upload", "The upload URL of demos.tf");
	g_ApiKey = CreateConVar("sm_demostf_apikey", "", "Your API key from demos.tf", FCVAR_PROTECTED);
	RegAdminCmd("sm_uploaddemo", Command_UploadDemo, ADMFLAG_RCON, "sm_uploaddemo <file> - uploads a demo to demos.tf");
}

public Action Command_UploadDemo(int client, int args)
{
	if (args != 1) {
		ReplyToCommand(client, "Usage: sm_uploaddemo <file>");
		return Plugin_Handled;
	}
	if (g_Form != null) {
		ReplyToCommand(client, "Another upload is still running.");
		return Plugin_Handled;
	}

	char file[PLATFORM_MAX_PATH];
	GetCmdArg(1, file, sizeof(file));
	if (!FileExists(file)) {
		ReplyToCommand(client, "%s does not exist.", file);
		return Plugin_Handled;
	}

	char apiKey[128];
	g_ApiKey.GetString(apiKey, sizeof(apiKey));

	// The form: four text fields and the demo itself as a file upload.
	g_Form = new CurlForm();
	g_Form.AddField("key", apiKey);
	g_Form.AddField("name", file);
	g_Form.AddField("red", "RED");
	g_Form.AddField("blu", "BLU");
	if (g_Form.AddFile("demo", file, "application/octet-stream") != CURL_FORMADD_OK) {
		delete g_Form;
		ReplyToCommand(client, "Cannot add %s to the upload.", file);
		return Plugin_Handled;
	}

	char url[256];
	g_UploadUrl.GetString(url, sizeof(url));

	g_Answer[0] = '\0';
	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetForm(g_Form);  // Setting a form makes the request a POST.
	easy.SetOptFunction(CURLOPT_WRITEFUNCTION, OnAnswerData);
	easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
	easy.SetTimeout(300);
	// The same as SetProgressCallback(OnUploadProgress, 2.0): the callback
	// is an option like the write callback, the interval a setting of its own.
	easy.SetOptFunction(CURLOPT_XFERINFOFUNCTION, OnUploadProgress);
	easy.SetProgressInterval(2.0);
	easy.PerformThread(OnUploaded);

	ReplyToCommand(client, "Uploading %s ...", file);
	return Plugin_Handled;
}

/**
 * Called for every piece of the answer. A piece may contain NUL bytes, so
 * it is copied with its length, not as a string. What does not fit into
 * g_Answer is dropped, but still reported as handled: any other return
 * value would end the transfer with CURLE_WRITE_ERROR.
 */
public int OnAnswerData(CurlEasy easy, const char[] buffer, const int bytes, const int nmemb)
{
	int length = bytes * nmemb;
	int used = strlen(g_Answer);
	int room = sizeof(g_Answer) - 1 - used;
	int count = length < room ? length : room;
	for (int i = 0; i < count; i++) {
		g_Answer[used + i] = buffer[i];
	}
	g_Answer[used + count] = '\0';
	return length;
}

/**
 * Called at most every two seconds during the upload and once at its end.
 * The upload counts are those of the whole request body: the demo and the
 * form around it.
 */
public Action OnUploadProgress(CurlEasy easy, int downloaded, int downloadTotal, int uploaded, int uploadTotal)
{
	if (uploadTotal > 0) {
		PrintToServer("Uploading: %d of %d bytes", uploaded, uploadTotal);
	}
	return Plugin_Continue;
}

public void OnUploaded(CurlEasy easy, CURLcode code)
{
	if (code != CURLE_OK) {
		char error[256];
		easy.GetError(code, error, sizeof(error));
		LogError("demos.tf upload failed: %s", error);
	} else if (StrContains(g_Answer, "STV available at: ") == 0) {
		// The link starts after the 18 characters of the prefix.
		PrintToChatAll("Demo uploaded: %s", g_Answer[18]);
		LogMessage("Demo uploaded: %s", g_Answer[18]);
	} else {
		LogError("demos.tf refused the upload (HTTP status %d): %s", easy.ResponseCode, g_Answer);
	}

	delete easy;
	delete g_Form;
}
