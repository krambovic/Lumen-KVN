package com.lumen.core.database

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.lumen.core.database.dao.NodeDao
import com.lumen.core.database.dao.SubscriptionDao
import com.lumen.core.database.model.NodeEntity
import com.lumen.core.database.model.SubscriptionEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class NodeDaoTest {

    private lateinit var db: AppDatabase
    private lateinit var nodeDao: NodeDao
    private lateinit var subscriptionDao: SubscriptionDao

    @Before
    fun createDb() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        nodeDao = db.nodeDao()
        subscriptionDao = db.subscriptionDao()
    }

    @After
    @Throws(IOException::class)
    fun closeDb() {
        db.close()
    }

    @Test
    fun testInsertAndQueryNode() = runBlocking {
        val node = NodeEntity(
            id = "node-1",
            name = "Test Vless Server",
            protocol = "vless",
            server = "192.168.1.1",
            port = 443,
            link = "vless://test",
            outboundJson = "{}",
            pingMs = 45,
            subscriptionId = "sub-1",
            isAutoNode = false
        )
        nodeDao.insertNode(node)

        val nodes = nodeDao.getNodes().first()
        assertEquals(1, nodes.size)
        assertEquals("Test Vless Server", nodes[0].name)
        assertEquals("vless", nodes[0].protocol)
        assertEquals(45, nodes[0].pingMs)

        val fetchedNode = nodeDao.getNodeById("node-1").first()
        assertEquals("Test Vless Server", fetchedNode?.name)
    }

    @Test
    fun testUpdatePing() = runBlocking {
        val node = NodeEntity(
            id = "node-2",
            name = "Test Vmess",
            protocol = "vmess",
            server = "10.0.0.1",
            port = 8080,
            link = "vmess://test",
            pingMs = null
        )
        nodeDao.insertNode(node)

        var fetched = nodeDao.getNodeById("node-2").first()
        assertNull(fetched?.pingMs)

        nodeDao.updatePing("node-2", 120)

        fetched = nodeDao.getNodeById("node-2").first()
        assertEquals(120, fetched?.pingMs)
    }

    @Test
    fun getNodesByIdsReturnsOnlyRequestedRows() = runBlocking {
        nodeDao.insertNodes(
            listOf(
                NodeEntity(
                    id = "node-query-1",
                    name = "First",
                    protocol = "vless",
                    server = "first.example",
                    port = 443,
                    link = "vless://first",
                    pingMs = 0
                ),
                NodeEntity(
                    id = "node-query-2",
                    name = "Second",
                    protocol = "vless",
                    server = "second.example",
                    port = 443,
                    link = "vless://second",
                    pingMs = 20
                )
            )
        )

        val selected = nodeDao.getNodesByIds(listOf("node-query-1"))

        assertEquals(listOf("node-query-1"), selected.map { it.id })
    }

    @Test
    fun testDeleteNode() = runBlocking {
        val node = NodeEntity(
            id = "node-3",
            name = "Node to Delete",
            protocol = "trojan",
            server = "example.com",
            port = 443,
            link = "trojan://test"
        )
        nodeDao.insertNode(node)

        var nodes = nodeDao.getNodes().first()
        assertEquals(1, nodes.size)

        nodeDao.deleteNodeById("node-3")

        nodes = nodeDao.getNodes().first()
        assertTrue(nodes.isEmpty())
    }

    @Test
    fun testSubscriptionAndNodes() = runBlocking {
        val sub = SubscriptionEntity(
            id = "sub-100",
            name = "My Subscription",
            url = "https://example.com/sub",
            lastUpdated = 1700000000L,
            autoUpdateEnabled = true
        )
        subscriptionDao.insertSubscription(sub)

        val node1 = NodeEntity(
            id = "node-101",
            name = "Sub Node 1",
            protocol = "shadowsocks",
            server = "ss1.com",
            port = 8388,
            link = "ss://test1",
            subscriptionId = "sub-100"
        )
        val node2 = NodeEntity(
            id = "node-102",
            name = "Sub Node 2",
            protocol = "shadowsocks",
            server = "ss2.com",
            port = 8388,
            link = "ss://test2",
            subscriptionId = "sub-100"
        )
        nodeDao.insertNodes(listOf(node1, node2))

        val subNodes = nodeDao.getNodesForSubscription("sub-100").first()
        assertEquals(2, subNodes.size)

        nodeDao.deleteNodesBySubscription("sub-100")
        val remainingNodes = nodeDao.getNodesForSubscription("sub-100").first()
        assertTrue(remainingNodes.isEmpty())
    }
}
