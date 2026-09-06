package com.lumen.ui

import com.lumen.ui.screens.LOG_LEVELS
import com.lumen.ui.screens.LumenStrings
import com.lumen.ui.screens.MULTIPLEX_PROTOCOLS
import com.lumen.ui.screens.SettingsUiState
import com.lumen.ui.screens.stringsForLanguage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the settings rows added for the sing-box-extended knobs: the option
 * lists must stay inside what the core accepts, the defaults must match
 * SingboxConfigOptions (so a fresh install produces the same config as before),
 * and every new label must exist in all four shipped languages.
 */
class SettingsOptionsTest {

    /** Values `sing-box-lumen check` accepts for log.level. */
    private val coreLogLevels =
        setOf("trace", "debug", "info", "warning", "error", "fatal", "panic")

    @Test
    fun logLevelsStayInsideWhatTheCoreParses() {
        assertTrue(LOG_LEVELS.isNotEmpty())
        LOG_LEVELS.forEach { level ->
            assertTrue("core rejects log level $level", level in coreLogLevels)
        }
        // "unknown log level: none" is fatal for the core, so it must never be offered.
        assertFalse("none" in LOG_LEVELS)
    }

    @Test
    fun multiplexProtocolsMatchTheCore() {
        assertEquals(listOf("smux", "yamux", "h2mux"), MULTIPLEX_PROTOCOLS)
    }

    @Test
    fun newOptionDefaultsMatchTheBuilderDefaults() {
        val state = SettingsUiState()
        assertEquals("smux", state.multiplexProtocol)
        assertEquals(4, state.multiplexMinStreams)
        assertTrue(state.multiplexPadding)
        assertFalse(state.multiplexBrutalEnabled)
        assertEquals(0, state.multiplexBrutalUpMbps)
        assertEquals(0, state.multiplexBrutalDownMbps)
        assertFalse(state.outboundTcpFastOpen)
        assertFalse(state.outboundTcpMultiPath)
        assertFalse(state.outboundUdpFragment)
        assertFalse(state.udpOverTcp)
        assertEquals(0, state.outboundConnectTimeoutSeconds)
        assertEquals(0, state.urlTestIdleTimeoutMinutes)
        assertTrue(state.urlTestInterruptExistConnections)
        assertTrue(state.loggingEnabled)
        assertFalse(state.proxyOnly)
        assertFalse(state.pingAutoDeleteUnreachable)
        assertEquals(1, state.pingAutoDeleteThresholdMs)
        assertTrue(state.autoCheckUpdates)
    }

    private val newLabels = listOf(
        "muxProtocolLabel", "muxMinStreamsLabel", "muxPadding", "muxPaddingDesc",
        "muxBrutal", "muxBrutalDesc", "muxBrutalUpLabel", "muxBrutalDownLabel",
        "outboundSection", "tcpFastOpen", "tcpFastOpenDesc", "tcpMultiPath",
        "tcpMultiPathDesc", "udpFragmentLabel", "udpFragmentDesc", "udpOverTcpLabel",
        "udpOverTcpDesc", "connectTimeoutLabel", "urlTestIdleTimeoutLabel",
        "urlTestInterrupt", "urlTestInterruptDesc", "loggingEnabled", "loggingEnabledDesc",
        "proxyOnly", "proxyOnlyDesc", "autoCheckUpdates", "autoCheckUpdatesDesc",
        "pingAutoDeleteUnreachable", "pingAutoDeleteUnreachableDesc",
        "pingAutoDeleteThresholdLabel"
    )

    @Test
    fun everyNewSettingsLabelIsTranslatedInAllLanguages() {
        listOf("en", "ru", "zh", "fa").forEach { language ->
            val strings = stringsForLanguage(language)
            newLabels.forEach { name ->
                val field = LumenStrings::class.java.getDeclaredField(name)
                field.isAccessible = true
                val value = field.get(strings) as String
                assertTrue("$language is missing $name", value.isNotBlank())
            }
        }
    }

    /**
     * LumenStrings is a class with var fields (a data class blew past ART's
     * constructor register limit), so copyFrom is the only thing keeping the
     * derived locales complete. It must reach every String field.
     */
    @Test
    fun copyFromCopiesEveryStringField() {
        val source = LumenStrings()
        val fields = LumenStrings::class.java.declaredFields
            .filter { it.type == String::class.java }
        fields.forEach {
            it.isAccessible = true
            it.set(source, "marker")
        }
        val copy = LumenStrings().copyFrom(source)
        fields.forEach {
            assertEquals("copyFrom skipped ${it.name}", "marker", it.get(copy))
        }
    }

    @Test
    fun russianCountLabelsUseTheCorrectCases() {
        val ru = stringsForLanguage("ru")

        assertEquals("1 группа", ru.groupCountLabel(1))
        assertEquals("2 группы", ru.groupCountLabel(2))
        assertEquals("5 групп", ru.groupCountLabel(5))
        assertEquals("21 группа", ru.groupCountLabel(21))
        assertEquals("22 группы", ru.groupCountLabel(22))
        assertEquals("25 групп", ru.groupCountLabel(25))

        assertEquals("1 сервер", ru.serverCountLabel(1))
        assertEquals("4 сервера", ru.serverCountLabel(4))
        assertEquals("11 серверов", ru.serverCountLabel(11))
    }
}
