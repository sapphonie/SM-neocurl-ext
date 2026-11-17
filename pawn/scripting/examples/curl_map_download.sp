/**
 * Example: download a map from a fast download server.
 *
 * Shows a download into a file with CurlFile: redirects, a connect timeout,
 * giving up on a stalled download, treating an HTTP error status as a failed
 * transfer, publishing the file only when it is complete, and a progress
 * callback that reports how far the download is and stops one that grows
 * too large.
 *
 *   sm_downloadmap cp_process_f12
 *
 * The map is fetched from <sm_downloadmap_url>/<map>.bsp into maps/. A
 * download larger than sm_downloadmap_max_size bytes is stopped.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <cURL>

public Plugin myinfo = {
	name = "cURL example: map download",
	author = "davenonymous",
	description = "Downloads maps from a fast download server",
	version = "1.0.0",
	url = "https://github.com/sapphonie/SM-neocurl-ext"
};

ConVar g_BaseUrl;
ConVar g_MaxSize;

public void OnPluginStart()
{
	g_BaseUrl = CreateConVar("sm_downloadmap_url", "https://fastdl.serveme.tf/maps",
	                         "Where sm_downloadmap fetches maps from, without a trailing slash");
	g_MaxSize = CreateConVar("sm_downloadmap_max_size", "536870912",
	                         "The most bytes a map may have; a larger download is stopped", _, true, 1.0);
	RegAdminCmd("sm_downloadmap", Command_DownloadMap, ADMFLAG_CHANGEMAP, "sm_downloadmap <map> - downloads a map");
}

public Action Command_DownloadMap(int client, int args)
{
	if (args != 1) {
		ReplyToCommand(client, "Usage: sm_downloadmap <map>");
		return Plugin_Handled;
	}

	char map[64];
	GetCmdArg(1, map, sizeof(map));

	char target[PLATFORM_MAX_PATH];
	Format(target, sizeof(target), "maps/%s.bsp", map);
	if (FileExists(target)) {
		ReplyToCommand(client, "%s is already there.", target);
		return Plugin_Handled;
	}

	// The download goes into a ".part" file first, so a broken download
	// never looks like a map. Paths are relative to the game directory.
	char partFile[PLATFORM_MAX_PATH];
	Format(partFile, sizeof(partFile), "%s.part", target);
	CurlFile file = new CurlFile(partFile, "wb");
	if (file == null) {
		ReplyToCommand(client, "Cannot write %s.", partFile);
		return Plugin_Handled;
	}

	char url[512];
	g_BaseUrl.GetString(url, sizeof(url));
	Format(url, sizeof(url), "%s/%s.bsp", url, map);

	CurlEasy easy = new CurlEasy();
	easy.SetUrl(url);
	easy.SetWriteFile(file);
	easy.SetFollowLocation(true);
	// A 404 page must not end up in the file: with CURLOPT_FAILONERROR a
	// status of 400 or above fails the transfer with CURLE_HTTP_RETURNED_ERROR.
	easy.SetOptInt(CURLOPT_FAILONERROR, 1);
	// A map can take minutes, so there is no limit on the whole transfer.
	// Instead: 10 seconds to connect, and give up when fewer than 1000
	// bytes per second arrive for 30 seconds.
	easy.SetOptInt(CURLOPT_CONNECTTIMEOUT, 10);
	easy.SetOptInt(CURLOPT_LOW_SPEED_LIMIT, 1000);
	easy.SetOptInt(CURLOPT_LOW_SPEED_TIME, 30);

	// The callbacks need the file handle and the map's name.
	DataPack pack = new DataPack();
	pack.WriteCell(file);
	pack.WriteString(map);

	// Report the progress once a second while the download runs.
	easy.SetProgressCallback(OnProgress, 1.0, pack);
	easy.PerformThread(OnDownloaded, pack);

	ReplyToCommand(client, "Downloading %s ...", url);
	return Plugin_Handled;
}

/**
 * Called at most once a second during the download, and once more at its
 * end. The totals are 0 when the server did not say how large the file is.
 */
public Action OnProgress(CurlEasy easy, int downloaded, int downloadTotal, int uploaded, int uploadTotal, DataPack pack)
{
	char map[64];
	pack.Reset();
	pack.ReadCell();
	pack.ReadString(map, sizeof(map));

	if (downloaded > g_MaxSize.IntValue) {
		LogError("%s is larger than %d bytes; stopping the download", map, g_MaxSize.IntValue);
		// The transfer ends with CURLE_ABORTED_BY_CALLBACK, and
		// OnDownloaded cleans up as after any failed download.
		return Plugin_Stop;
	}

	if (downloadTotal > 0) {
		// Float arithmetic: downloaded * 100 would overflow above 21 MB.
		int percent = RoundToFloor(float(downloaded) / float(downloadTotal) * 100.0);
		PrintToServer("Downloading %s: %d%% (%d of %d bytes)", map, percent, downloaded, downloadTotal);
	} else {
		PrintToServer("Downloading %s: %d bytes so far", map, downloaded);
	}
	return Plugin_Continue;
}

public void OnDownloaded(CurlEasy easy, CURLcode code, DataPack pack)
{
	pack.Reset();
	CurlFile file = pack.ReadCell();
	char map[64];
	pack.ReadString(map, sizeof(map));
	delete pack;

	char error[256];
	easy.GetError(code, error, sizeof(error));
	float seconds = easy.TotalTime;

	// Closing the file writes its last bytes to the disk.
	delete easy;
	delete file;

	char target[PLATFORM_MAX_PATH];
	Format(target, sizeof(target), "maps/%s.bsp", map);
	char partFile[PLATFORM_MAX_PATH];
	Format(partFile, sizeof(partFile), "%s.part", target);

	if (code != CURLE_OK) {
		DeleteFile(partFile);
		LogError("Download of %s failed: %s", map, error);
		return;
	}

	if (!RenameFile(target, partFile)) {
		DeleteFile(partFile);
		LogError("Cannot move %s to %s", partFile, target);
		return;
	}

	LogMessage("Downloaded %s: %d bytes in %.1f seconds", target, FileSize(target), seconds);
}
