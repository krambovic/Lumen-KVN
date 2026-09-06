package com.lumen.app.update

import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

internal data class AndroidRelease(
    val tag: String,
    val version: String,
    val releaseUrl: String,
    val apkName: String?,
    val apkUrl: String?
)

internal data class AndroidUpdateState(
    val isChecking: Boolean = false,
    val latest: AndroidRelease? = null,
    val updateAvailable: Boolean = false,
    val error: String? = null,
    val checked: Boolean = false,
    val isDownloading: Boolean = false,
    val downloadProgress: Int? = null,
    val downloadedApkPath: String? = null,
    val installRequestId: Long = 0L
)

/**
 * GitHub's `/releases/latest` belongs to the Windows release stream in this repository.
 * Android releases are selected exclusively by their `android-v…` tag.
 */
internal object AndroidUpdateChecker {
    const val AUTO_CHECK_INTERVAL_MS = 24L * 60L * 60L * 1000L
    const val RELEASES_API =
        "https://api.github.com/repos/krambovic/Lumen/releases?per_page=100"

    fun isAutoCheckDue(nowMs: Long, lastCheckMs: Long): Boolean =
        lastCheckMs <= 0L || nowMs - lastCheckMs >= AUTO_CHECK_INTERVAL_MS

    fun fetch(supportedAbis: List<String>): AndroidRelease {
        val connection = URL(RELEASES_API).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 10_000
            connection.readTimeout = 15_000
            connection.setRequestProperty("Accept", "application/vnd.github+json")
            connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            connection.setRequestProperty("User-Agent", "Lumen-Android-Updater")
            val status = connection.responseCode
            if (status !in 200..299) {
                throw IllegalStateException("GitHub returned HTTP $status")
            }
            val body = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            return selectLatest(body, supportedAbis)
                ?: throw IllegalStateException("No published Android release was found")
        } finally {
            connection.disconnect()
        }
    }

    fun selectLatest(json: String, supportedAbis: List<String>): AndroidRelease? {
        val releases = JSONArray(json)
        return buildList {
            for (index in 0 until releases.length()) {
                val release = releases.optJSONObject(index) ?: continue
                if (release.optBoolean("draft") || release.optBoolean("prerelease")) continue
                val tag = release.optString("tag_name").trim()
                val version = androidVersionFromTag(tag) ?: continue
                val assets = release.optJSONArray("assets") ?: JSONArray()
                val apk = selectApkAsset(
                    buildList {
                        for (assetIndex in 0 until assets.length()) {
                            val asset = assets.optJSONObject(assetIndex) ?: continue
                            val name = asset.optString("name").trim()
                            val url = asset.optString("browser_download_url").trim()
                            if (name.endsWith(".apk", ignoreCase = true) && url.startsWith("https://")) {
                                add(name to url)
                            }
                        }
                    },
                    supportedAbis
                )
                // A release page without an APK compatible with this device cannot
                // be installed in-app and must not hide an older installable release.
                if (apk == null) continue
                add(
                    AndroidRelease(
                        tag = tag,
                        version = version,
                        releaseUrl = release.optString("html_url").trim(),
                        apkName = apk?.first,
                        apkUrl = apk?.second
                    )
                )
            }
        }.maxWithOrNull { left, right -> compareVersions(left.version, right.version) }
    }

    fun isNewer(candidate: String, current: String): Boolean =
        compareVersions(candidate, current) > 0

    internal fun androidVersionFromTag(tag: String): String? {
        val match = ANDROID_TAG.matchEntire(tag.trim()) ?: return null
        val version = match.groupValues[1]
        return version.takeIf { VERSION.matches(it) }
    }

    internal fun selectApkAsset(
        assets: List<Pair<String, String>>,
        supportedAbis: List<String>
    ): Pair<String, String>? {
        if (assets.isEmpty()) return null
        val normalizedAbis = supportedAbis.map { it.lowercase(Locale.US) }
        normalizedAbis.forEach { abi ->
            assets.firstOrNull { (name, _) ->
                name.lowercase(Locale.US).contains(abi)
            }?.let { return it }
        }
        return assets.firstOrNull { (name, _) ->
            name.contains("universal", ignoreCase = true)
        }
    }

    private fun compareVersions(left: String, right: String): Int {
        val l = versionParts(left)
        val r = versionParts(right)
        val count = maxOf(l.size, r.size)
        for (index in 0 until count) {
            val compared = (l.getOrElse(index) { 0 }).compareTo(r.getOrElse(index) { 0 })
            if (compared != 0) return compared
        }
        return 0
    }

    private fun versionParts(value: String): List<Int> =
        VERSION_PART.findAll(value).map { it.value.toIntOrNull() ?: 0 }.toList()

    private val ANDROID_TAG = Regex("^android[-_/]v?(.+)$", RegexOption.IGNORE_CASE)
    private val VERSION = Regex("^\\d+(?:\\.\\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
    private val VERSION_PART = Regex("\\d+")
}
